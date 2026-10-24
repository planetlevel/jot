"""What the application's libraries can do, for the assistant.

An application does more than its own code says. The libraries it ships with, and the server it runs in, can read files, parse XML, evaluate
expressions, call other services and deserialize what a request sends, and a framework may use them for the application without its code ever
naming them. A sensor on a library method sees that, and static analysis of the application's own source can't.

This finds the libraries a project has, from its build files, from the jars it ships and from the local build caches, lists the public classes of
a jar and the public methods of a class, and knows which kinds of library are worth a look and what each can do. It reads names only, and only
from jars. The paths of the jars are never given to the model, it names a library as group:artifact.

Jars are read from the project folder and from the Maven and Gradle caches in the person's home, and only the ones the project's own build files
lead to. Nothing is run except javap, to list the public methods of a class.
"""

import fnmatch
import io
import os
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

MAX_POMS = 12
MAX_LIBRARIES = 700
MAX_DEPTH = 4                    # how far down the dependencies of dependencies are followed
MAX_MATCHES = 80
MAX_JAR_BYTES = 80 * 1024 * 1024
MAX_NESTED_BYTES = 40 * 1024 * 1024
SEARCH_SECONDS = 15
JAVAP_SECONDS = 15
MAX_DESCRIPTION = 9000

SKIP_WALK = {".git", ".hg", ".svn", "node_modules", ".idea", ".vscode", ".gradle", ".mvn", "venv", ".venv", "__pycache__", "src"}
# where a project keeps the jars it ships, relative to the folder. A glob where a name varies
JAR_DIRS = ("WEB-INF/lib", "lib", "libs", "target/dependency", "target/lib", "target/*/WEB-INF/lib", "target/*/BOOT-INF/lib", "build/libs", "build/*/WEB-INF/lib",
            "webapp/WEB-INF/lib", "src/main/webapp/WEB-INF/lib")
CLASS_NAME = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")

# What a kind of library can do that is worth watching, and the methods to start from. The first column is matched against group:artifact. The methods
# are what these libraries have had for years, and the version in the project may differ, so each is checked with describe_class before it is used.
# kind is library for something the application uses, and server for what it runs in.
HINTS = [
    (r"jackson-databind", "library", "turns JSON into objects, which is deserialization of what a request sends, and default typing makes it unsafe",
     ["com.fasterxml.jackson.databind.ObjectMapper.readValue", "com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping"]),
    (r"snakeyaml", "library", "turns YAML into objects, and the default loader can build any class",
     ["org.yaml.snakeyaml.Yaml.load", "org.yaml.snakeyaml.Yaml.loadAs"]),
    (r"xstream", "library", "turns XML into any object", ["com.thoughtworks.xstream.XStream.fromXML"]),
    (r"google\.code\.gson:gson", "library", "turns JSON into objects", ["com.google.gson.Gson.fromJson"]),
    (r"commons-collections|commons-beanutils|:groovy$|:javassist", "library",
     "on the classpath it gives a deserialization attack the classes it needs, whether or not the application calls it",
     ["org.apache.commons.beanutils.BeanUtils.populate", "org.apache.commons.beanutils.PropertyUtils.setProperty"]),
    (r"log4j-core", "library", "formats log messages, and its lookups can fetch from JNDI and read the environment",
     ["org.apache.logging.log4j.core.lookup.JndiLookup.lookup", "org.apache.logging.log4j.core.lookup.StrSubstitutor.replace"]),
    (r"commons-text", "library", "substitutes ${...} in text, and its lookups can run scripts, read files and fetch URLs",
     ["org.apache.commons.text.StringSubstitutor.replace"]),
    (r"commons-fileupload", "library", "receives uploaded files and writes them to disk",
     ["org.apache.commons.fileupload.servlet.ServletFileUpload.parseRequest", "org.springframework.web.multipart.MultipartFile.transferTo"]),
    (r"commons-io", "library", "reads and writes files by path",
     ["org.apache.commons.io.FileUtils.readFileToString", "org.apache.commons.io.FileUtils.writeStringToFile", "org.apache.commons.io.FileUtils.copyFile",
      "org.apache.commons.io.FileUtils.deleteDirectory"]),
    (r"commons-compress|zip4j|:truezip", "library", "unpacks archives, where an entry's name can point outside the folder",
     ["org.apache.commons.compress.archivers.ArchiveInputStream.getNextEntry", "org.apache.commons.compress.archivers.zip.ZipFile.getInputStream"]),
    (r"httpclient$|httpclient5|httpcore", "library", "makes outbound HTTP requests to a URL the application chooses",
     ["org.apache.http.impl.client.CloseableHttpClient.execute", "org.apache.hc.client5.http.impl.classic.CloseableHttpClient.execute"]),
    (r"okhttp|retrofit|jersey-client|resteasy-client|:unirest|:feign", "library", "makes outbound HTTP requests to a URL the application chooses",
     ["okhttp3.Call.execute", "okhttp3.Call.enqueue", "javax.ws.rs.client.Invocation.invoke"]),
    (r"spring-web$|spring-webflux", "library", "RestTemplate and WebClient make outbound HTTP requests, and the DataBinder fills objects from request parameters",
     ["org.springframework.web.client.RestTemplate.execute", "org.springframework.web.reactive.function.client.WebClient.create",
      "org.springframework.validation.DataBinder.bind"]),
    (r"hibernate-core|jakarta\.persistence|hibernate-entitymanager", "library", "runs HQL and native SQL built by the application, besides the SQL it generates",
     ["org.hibernate.Session.createQuery", "org.hibernate.Session.createNativeQuery", "org.hibernate.Session.createSQLQuery"]),
    (r"spring-jdbc|spring-data-jdbc|jdbi|:jooq|commons-dbutils", "library", "runs SQL through a helper that hides the JDBC calls",
     ["org.springframework.jdbc.core.JdbcTemplate.query", "org.springframework.jdbc.core.JdbcTemplate.update", "org.springframework.jdbc.core.JdbcTemplate.execute"]),
    (r"mybatis", "library", "runs SQL from mapper files, where ${} is pasted into the statement",
     ["org.apache.ibatis.session.SqlSession.selectList", "org.apache.ibatis.session.SqlSession.update"]),
    (r"freemarker", "library", "renders templates, which is code execution when the template comes from the request",
     ["freemarker.template.Template.process"]),
    (r"velocity", "library", "renders templates, which is code execution when the template comes from the request",
     ["org.apache.velocity.app.VelocityEngine.evaluate", "org.apache.velocity.app.Velocity.evaluate"]),
    (r"thymeleaf", "library", "renders templates and evaluates expressions in them", ["org.thymeleaf.TemplateEngine.process"]),
    (r"spring-expression", "library", "evaluates expressions, which is code execution when the text comes from the request",
     ["org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression"]),
    (r":ognl|:mvel|:groovy$|groovy-all|:jexl|:nashorn|:rhino|:jython", "library", "runs scripts and expressions as code",
     ["ognl.Ognl.getValue", "org.mvel2.MVEL.eval", "groovy.lang.GroovyShell.evaluate", "org.apache.commons.jexl3.JexlExpression.evaluate"]),
    (r"xerces|dom4j|jdom|:xalan|saxon|jaxb|xmlbeans|woodstox|stax", "library", "parses XML, which can fetch external entities and read files unless it is set not to",
     ["org.dom4j.io.SAXReader.read", "org.jdom2.input.SAXBuilder.build", "javax.xml.parsers.DocumentBuilder.parse"]),
    (r"spring-ldap|unboundid|:ldaptive|apacheds", "library", "queries a directory, with filters the application builds",
     ["org.springframework.ldap.core.LdapTemplate.search", "com.unboundid.ldap.sdk.LDAPConnection.search"]),
    (r"kafka-clients|spring-kafka", "library", "messages arrive and leave here, and a consumer is an entry point of its own",
     ["org.apache.kafka.clients.consumer.KafkaConsumer.poll", "org.apache.kafka.clients.producer.KafkaProducer.send"]),
    (r"amqp-client|spring-rabbit|spring-amqp|activemq|artemis|jms|:pulsar|:nats|aws-java-sdk-sqs|:sqs", "library", "messages arrive and leave here, and a listener is an entry point of its own",
     ["com.rabbitmq.client.Channel.basicPublish", "javax.jms.MessageProducer.send", "javax.jms.MessageConsumer.receive"]),
    (r"software\.amazon\.awssdk|aws-java-sdk|google-cloud|azure-|:minio", "library", "reads and writes cloud storage and calls cloud services with the application's credentials", []),
    (r"javax\.mail|jakarta\.mail|spring-context-support|:commons-email", "library", "sends mail, to addresses and with content the application chooses",
     ["javax.mail.Transport.send", "jakarta.mail.Transport.send"]),
    (r":jsch|sshj|commons-net|:ftp", "library", "reaches other machines over SSH, FTP and the like",
     ["com.jcraft.jsch.JSch.getSession", "org.apache.commons.net.ftp.FTPClient.retrieveFile"]),
    (r"jjwt|java-jwt|nimbus-jose|:jose4j|:jwt", "library", "checks and creates tokens, where skipping the signature check or accepting the none algorithm is the flaw to look for",
     ["io.jsonwebtoken.JwtParser.parse", "com.auth0.jwt.JWTVerifier.verify", "com.nimbusds.jwt.SignedJWT.parse"]),
    (r"bouncycastle|:bcprov|:tink|:jasypt|:keyczar", "library", "does the cryptography, and the algorithm and key size are chosen by the caller",
     ["org.bouncycastle.jce.provider.BouncyCastleProvider.addAlgorithm"]),
    (r"spring-security|:shiro|:keycloak|pac4j|:oauth2", "library", "decides who a user is and what they may do",
     ["org.springframework.security.authentication.ProviderManager.authenticate", "org.apache.shiro.subject.Subject.login",
      "org.springframework.security.access.AccessDecisionManager.decide"]),
    (r"jedis|lettuce|redisson|spring-data-redis|mongo|elasticsearch|cassandra|couchbase|:neo4j|:dynamodb", "library",
     "another data store, queried with values the application builds", ["com.mongodb.client.MongoCollection.find", "redis.clients.jedis.Jedis.eval"]),
    (r":jsoup", "library", "parses HTML, and Jsoup.connect fetches a URL", ["org.jsoup.Jsoup.connect", "org.jsoup.Jsoup.parse"]),
    (r"tika|pdfbox|:poi|poi-ooxml|itext|openpdf|:docx4j", "library", "parses documents people upload, which are XML and archives inside",
     ["org.apache.tika.parser.AutoDetectParser.parse", "org.apache.poi.ss.usermodel.WorkbookFactory.create", "org.apache.pdfbox.pdmodel.PDDocument.load"]),
    (r"actuator", "library", "exposes the application's environment, beans, heap and shutdown over HTTP", []),
    (r"com\.h2database:h2|hsqldb|:derby|sqlite-jdbc", "library", "an embedded database that can read files and run Java through aliases, and may have a web console on",
     ["org.h2.Driver.connect", "org.h2.tools.Server.createWebServer"]),
    (r"mysql-connector|mariadb-java|postgresql|ojdbc|mssql-jdbc|:db2", "library", "a JDBC driver, so the application talks to that database", ["java.sql.DriverManager.getConnection"]),
    (r"spring-webmvc", "server", "maps requests to controllers and fills their parameters and bodies from the request",
     ["org.springframework.web.servlet.DispatcherServlet.doDispatch", "org.springframework.web.servlet.HandlerAdapter.handle"]),
    (r"tomcat-embed-core|:catalina|tomcat-catalina", "server", "the application server, which serves files, compiles JSP, keeps sessions and can have its manager application on",
     ["org.apache.catalina.servlets.DefaultServlet.serveResource", "org.apache.jasper.servlet.JspServlet.service", "org.apache.catalina.session.ManagerBase.createSession"]),
    (r"jetty-server|jetty-webapp", "server", "the application server, which serves files and keeps sessions",
     ["org.eclipse.jetty.server.session.SessionHandler.newHttpSession", "org.eclipse.jetty.servlet.DefaultServlet.doGet"]),
    (r"undertow|wildfly|jboss|weblogic|websphere|:liberty|payara|glassfish", "server", "the application server and what it brings, such as its own libraries for XML, JNDI and management", []),
]
_HINTS = [(re.compile(rx), kind, what, methods) for rx, kind, what, methods in HINTS]

# the platform, which every Java application has and the libraries above are built on. The methods are the ones where a request's data becomes an action
PLATFORM = [
    ("reads objects from bytes, which runs code in the classes it finds", ["java.io.ObjectInputStream.readObject"]),
    ("evaluates scripts", ["javax.script.ScriptEngine.eval"]),
    ("looks things up by name, including over the network", ["javax.naming.Context.lookup", "javax.naming.directory.DirContext.search"]),
    ("parses XML", ["javax.xml.parsers.DocumentBuilder.parse", "javax.xml.parsers.SAXParser.parse", "javax.xml.transform.Transformer.transform",
                    "javax.xml.stream.XMLInputFactory.createXMLStreamReader"]),
    ("loads classes and calls methods by name", ["java.lang.Class.forName", "java.lang.reflect.Method.invoke", "java.net.URLClassLoader.<init>"]),
    ("opens connections to hosts", ["java.net.URL.openConnection", "java.net.Socket.connect", "java.net.http.HttpClient.send"]),
    ("starts processes", ["java.lang.ProcessBuilder.start", "java.lang.Runtime.exec"]),
    ("reads and writes files", ["java.io.FileInputStream.<init>", "java.nio.file.Files.newInputStream", "java.nio.file.Files.write"]),
]


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child(node, name):
    for c in node:
        if _local(c.tag) == name:
            return c
    return None


def _text(node, name):
    c = _child(node, name)
    return (c.text or "").strip() if c is not None and c.text else ""


def _properties(root):
    props = {}
    block = _child(root, "properties")
    if block is not None:
        for p in block:
            props[_local(p.tag)] = (p.text or "").strip()
    parent = _child(root, "parent")
    for key in ("version", "groupId"):
        v = _text(root, key) or (_text(parent, key) if parent is not None else "")
        props["project." + key] = v
        props["pom." + key] = v
    return props


def _fill(text, props):
    for _ in range(4):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), text or "")
        if new == text:
            break
        text = new
    return text


def _read_pom(path):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    props = _properties(root)
    managed = {}
    dm = _child(root, "dependencyManagement")
    deps = []
    for holder, into in ((dm, None), (root, deps)):
        if holder is None:
            continue
        block = _child(holder, "dependencies") if into is not None else (_child(dm, "dependencies") if dm is not None else None)
        if block is None:
            continue
        for d in block:
            if _local(d.tag) != "dependency":
                continue
            g, a = _fill(_text(d, "groupId"), props), _fill(_text(d, "artifactId"), props)
            v = _fill(_text(d, "version"), props)
            if "${" in v:
                v = ""
            item = {"group": g, "artifact": a, "version": v, "scope": _text(d, "scope") or "compile", "optional": _text(d, "optional") == "true"}
            if into is None:
                if v:
                    managed[(g, a)] = v
            else:
                deps.append(item)
    for d in deps:
        d["version"] = d["version"] or managed.get((d["group"], d["artifact"]), "")
    return {"deps": deps, "props": props, "parent": _child(root, "parent")}


def _m2():
    return os.path.join(os.path.expanduser("~"), ".m2", "repository")


def _versions(g, a):
    base = os.path.join(_m2(), *g.split("."), a)
    try:
        found = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
    except OSError:
        return []
    return sorted(found, key=lambda d: os.path.getmtime(os.path.join(base, d)), reverse=True)


def _m2_files(g, a, v):
    """The jar and the pom of a Maven coordinate in the local repository, either may be None. With no version, the newest that is there."""
    if not g or not a:
        return None, None, v
    if not v:
        found = _versions(g, a)
        if not found:
            return None, None, v
        v = found[0]
    base = os.path.join(_m2(), *g.split("."), a, v)
    jar, pom = os.path.join(base, "%s-%s.jar" % (a, v)), os.path.join(base, "%s-%s.pom" % (a, v))
    return (jar if os.path.isfile(jar) else None), (pom if os.path.isfile(pom) else None), v


def _gradle_jar(g, a, v):
    base = os.path.join(os.path.expanduser("~"), ".gradle", "caches", "modules-2", "files-2.1", g, a)
    if not os.path.isdir(base):
        return None, v
    versions = [v] if v and os.path.isdir(os.path.join(base, v)) else sorted(os.listdir(base), key=lambda d: os.path.getmtime(os.path.join(base, d)), reverse=True)
    for ver in versions:
        for root, _, files in os.walk(os.path.join(base, ver)):
            for f in files:
                if f.endswith(".jar") and not f.endswith(("-sources.jar", "-javadoc.jar")):
                    return os.path.join(root, f), ver
    return None, v


class Libraries:
    """The libraries of one project folder, found once and looked into on request."""

    def __init__(self, root):
        self.root = root
        self.items = {}          # group:artifact to {"id", "version", "how", "jar", "nested", "scope"}
        self.notes = []
        self._find()

    # ------------------------------------------------------------------ finding them

    def _add(self, key, version, how, jar=None, nested=None, scope=""):
        # a jar found by its file name has no group, and is the same library as one the build files name when the artifact is
        artifact = key.split(":", 1)[-1]
        if key.startswith("?:"):
            same = [k for k in self.items if not k.startswith("?:") and k.split(":", 1)[-1] == artifact]
            if same:
                key = same[0]
        elif "?:" + artifact in self.items:
            old = self.items.pop("?:" + artifact)
            jar, nested, version = jar or old["jar"], nested or old["nested"], version or old["version"]
        if key in self.items:
            have = self.items[key]
            if not have.get("jar") and jar:
                have["jar"] = jar
            if not have.get("nested") and nested:
                have["nested"] = nested
            if not have.get("version") and version:
                have["version"] = version
            return
        if len(self.items) < MAX_LIBRARIES:
            self.items[key] = {"id": key, "version": version, "how": how, "jar": jar, "nested": nested, "scope": scope}

    def _walk(self, wanted):
        """Files under the project that a predicate wants, leaving out what is neither a build file nor a place jars are kept."""
        out = []
        for here, dirs, files in os.walk(self.root):
            depth = os.path.relpath(here, self.root).count(os.sep)
            dirs[:] = [d for d in dirs if d not in SKIP_WALK and not d.startswith(".") and depth < 3]
            for f in files:
                if wanted(f):
                    out.append(os.path.join(here, f))
        return out

    def _find(self):
        poms = sorted(self._walk(lambda f: f == "pom.xml"), key=lambda p: p.count(os.sep))[:MAX_POMS]
        for path in poms:
            self._from_pom(path)
        for path in self._walk(lambda f: f in ("build.gradle", "build.gradle.kts")):
            self._from_gradle(path)
        for pattern in JAR_DIRS:
            for folder in _glob_dirs(self.root, pattern):
                for f in sorted(os.listdir(folder)):
                    if f.endswith(".jar"):
                        self._from_jar(os.path.join(folder, f), "a jar in " + os.path.relpath(folder, self.root).replace(os.sep, "/"))
        for path in self._walk(lambda f: f.endswith((".jar", ".war"))):
            rel = os.path.relpath(path, self.root)
            if rel.split(os.sep)[0] in ("target", "build") and rel.count(os.sep) == 1 and not rel.endswith(("-sources.jar", "-javadoc.jar")):
                self._from_fat(path)
        if not self.items:
            self.notes.append("No build file or jar that lists libraries was found in the project folder")

    def _from_pom(self, path):
        pom = _read_pom(path)
        if pom is None:
            return
        rel = os.path.relpath(path, self.root).replace(os.sep, "/")
        queue = []
        for d in pom["deps"]:
            if d["scope"] == "test" or d["optional"]:
                continue
            key = "%s:%s" % (d["group"], d["artifact"])
            jar, _, v = _m2_files(d["group"], d["artifact"], d["version"])
            self._add(key, v or d["version"], "declared in " + rel, jar, scope=d["scope"])
            queue.append((d["group"], d["artifact"], v or d["version"], 1, key))
        # what those need in turn, from the poms in the local repository
        seen = set()
        while queue and len(self.items) < MAX_LIBRARIES:
            g, a, v, depth, via = queue.pop(0)
            if depth > MAX_DEPTH or (g, a) in seen:
                continue
            seen.add((g, a))
            _, pom_file, v = _m2_files(g, a, v)
            sub = _read_pom(pom_file) if pom_file else None
            if sub is None:
                continue
            for d in sub["deps"]:
                if d["scope"] not in ("compile", "runtime") or d["optional"]:
                    continue
                key = "%s:%s" % (d["group"], d["artifact"])
                jar, _, ver = _m2_files(d["group"], d["artifact"], d["version"])
                if not d["group"] or not jar and not ver:
                    continue
                self._add(key, ver or d["version"], "needed by " + via, jar, scope=d["scope"])
                queue.append((d["group"], d["artifact"], ver or d["version"], depth + 1, key))

    def _from_gradle(self, path):
        text = _read(path)
        rel = os.path.relpath(path, self.root).replace(os.sep, "/")
        for m in re.finditer(r"""\b(?:implementation|api|compile|runtimeOnly|compileOnly|runtime|providedCompile)\s*\(?\s*['"]([\w.\-]+):([\w.\-]+)(?::([\w.\-${}]+))?['"]""", text):
            g, a, v = m.group(1), m.group(2), m.group(3) or ""
            if "$" in v:
                v = ""
            jar, ver = _gradle_jar(g, a, v)
            self._add("%s:%s" % (g, a), ver or v, "declared in " + rel, jar)

    def _from_jar(self, path, how):
        key, version = _coordinate(path)
        self._add(key, version, how, path)

    def _from_fat(self, path):
        """A jar or war that holds the libraries it was built with, like a Spring Boot jar, which is how a library nobody declared by hand still gets in."""
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                nested = [n for n in names if n.endswith(".jar") and re.search(r"(BOOT-INF|WEB-INF)/lib/|^lib/", n)]
                for n in nested[:MAX_LIBRARIES]:
                    base = os.path.basename(n)
                    key, version = _coordinate(base)
                    self._add(key, version, "built into " + os.path.basename(path), nested=(path, n))
                if any(n.startswith("BOOT-INF/") for n in names):
                    self.notes.append("%s is a Spring Boot jar, which brings its own server" % os.path.basename(path))
        except (OSError, zipfile.BadZipFile):
            pass

    # ------------------------------------------------------------------ what there is to say

    def listing(self):
        """The libraries as the model sees them, and what is worth a look in them."""
        direct, transitive, other = [], [], []
        for key, item in sorted(self.items.items()):
            line = "%s:%s" % (key, item["version"]) if item["version"] else key
            (direct if item["how"].startswith("declared") else transitive if item["how"].startswith("needed") else other).append(line)
        hints, servers = [], []
        for key, item in sorted(self.items.items()):
            for rx, kind, what, methods in _HINTS:
                if rx.search(key):
                    entry = {"library": key, "version": item["version"], "can": what, "methods": methods}
                    (servers if kind == "server" else hints).append(entry)
        return {"declared": direct, "needed_by_those": transitive, "shipped": other, "application_server_and_framework": servers, "libraries_worth_a_look": hints,
                "the_platform_itself": [{"can": what, "methods": methods} for what, methods in PLATFORM], "notes": self.notes,
                "how_to_use_this": "These are starting points from what such libraries have had, the version here may differ. Check a class with search_libraries and "
                                   "describe_class before you watch it, and say which version you are assuming. A library the application's code never names can still "
                                   "be used by the framework or the server."}

    # ------------------------------------------------------------------ looking inside

    def _jars(self, library=None):
        """The libraries to look in, as (key, opener) where opener gives the bytes of a jar on demand. library narrows it to group:artifact or a part of one."""
        for key, item in sorted(self.items.items()):
            if library and library.lower() not in key.lower():
                continue
            if item.get("jar"):
                yield key, item["jar"]
            elif item.get("nested"):
                yield key, item["nested"]

    @staticmethod
    def _names(source):
        try:
            if isinstance(source, tuple):
                with zipfile.ZipFile(source[0]) as outer:
                    info = outer.getinfo(source[1])
                    if info.file_size > MAX_NESTED_BYTES:
                        return []
                    with zipfile.ZipFile(io.BytesIO(outer.read(info))) as z:
                        return z.namelist()
            if os.path.getsize(source) > MAX_JAR_BYTES:
                return []
            with zipfile.ZipFile(source) as z:
                return z.namelist()
        except (OSError, zipfile.BadZipFile, KeyError):
            return []

    def search(self, pattern, library=None):
        """Classes whose name matches a regular expression, in the libraries of the project."""
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise ValueError("that isn't a regular expression, %s" % e)
        end = time.time() + SEARCH_SECONDS
        matches, searched, cut = [], 0, False
        for key, source in self._jars(library):
            if time.time() > end:
                cut = True
                break
            searched += 1
            for name in self._names(source):
                if not name.endswith(".class") or name.startswith("META-INF/") or name.endswith("module-info.class") or re.search(r"\$\d", name):
                    continue
                cls = name[:-6].replace("/", ".")
                for prefix in ("BOOT-INF.classes.", "WEB-INF.classes."):
                    if cls.startswith(prefix):
                        cls = cls[len(prefix):]
                if rx.search(cls):
                    matches.append({"library": key, "class": cls})
                    if len(matches) >= MAX_MATCHES:
                        return {"matches": matches, "searched_libraries": searched, "more": True}
        return {"matches": matches, "searched_libraries": searched, "more": cut,
                "note": None if searched else "no jar of the project's libraries could be found to look in, so only what the build files say is known"}

    def describe(self, class_name, library=None):
        """The public methods and fields of a class, from javap, in the libraries or in the JDK."""
        if not CLASS_NAME.match(class_name or ""):
            raise ValueError("%r isn't a class name, give it with its package like com.acme.Thing" % (class_name,))
        javap = shutil.which("javap")
        if not javap:
            raise ValueError("javap, which comes with the JDK, isn't on this machine, so methods can't be listed. Use what you know of the library and say which "
                             "version you are assuming")
        entry = class_name.replace(".", "/") + ".class"
        with tempfile.TemporaryDirectory() as scratch:
            for key, source in self._jars(library):
                path = None
                try:
                    if isinstance(source, tuple):
                        with zipfile.ZipFile(source[0]) as outer:
                            info = outer.getinfo(source[1])
                            if info.file_size > MAX_NESTED_BYTES:
                                continue
                            data = outer.read(info)
                        with zipfile.ZipFile(io.BytesIO(data)) as z:
                            if entry not in z.namelist():
                                continue
                        path = os.path.join(scratch, os.path.basename(source[1]))
                        with open(path, "wb") as f:
                            f.write(data)
                    else:
                        with zipfile.ZipFile(source) as z:
                            if entry not in z.namelist():
                                continue
                        path = source
                except (OSError, zipfile.BadZipFile, KeyError):
                    continue
                return self._javap(javap, ["-public", "-cp", path, class_name], key)
        if re.match(r"^(java|javax|jdk)\.", class_name):
            return self._javap(javap, ["-public", class_name], "the JDK")
        raise ValueError("%s isn't in any library of the project%s, search_libraries finds classes by name" % (class_name, " that matches " + library if library else ""))

    @staticmethod
    def _javap(javap, args, where):
        try:
            done = subprocess.run([javap] + args, capture_output=True, text=True, timeout=JAVAP_SECONDS)
        except (OSError, subprocess.SubprocessError) as e:
            raise ValueError("javap couldn't be run, %s" % e)
        if done.returncode != 0:
            raise ValueError("javap couldn't read it, %s" % (done.stderr.strip().splitlines() or ["it failed"])[0])
        text = done.stdout.strip()
        return {"library": where, "declaration": text[:MAX_DESCRIPTION], "cut": len(text) > MAX_DESCRIPTION}


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _glob_dirs(root, pattern):
    """The directories under root that a relative pattern with * in it names."""
    here = [root]
    for part in pattern.split("/"):
        nxt = []
        for base in here:
            if "*" in part:
                try:
                    nxt += [os.path.join(base, d) for d in sorted(os.listdir(base)) if fnmatch.fnmatch(d, part) and os.path.isdir(os.path.join(base, d))]
                except OSError:
                    pass
            elif os.path.isdir(os.path.join(base, part)):
                nxt.append(os.path.join(base, part))
        here = nxt
    return here


def _coordinate(jar):
    """group:artifact and the version of a jar, from the pom.properties Maven puts in it, or else from its file name, where the group isn't known."""
    base = os.path.basename(jar)
    if os.path.isfile(jar):
        try:
            with zipfile.ZipFile(jar) as z:
                for name in z.namelist():
                    if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                        props = dict(line.split("=", 1) for line in z.read(name).decode("utf-8", "replace").splitlines() if "=" in line and not line.startswith("#"))
                        if props.get("groupId") and props.get("artifactId"):
                            return "%s:%s" % (props["groupId"].strip(), props["artifactId"].strip()), props.get("version", "").strip()
        except (OSError, zipfile.BadZipFile, KeyError):
            pass
    m = re.match(r"^(.*?)-(\d[\w.\-]*)\.jar$", base)
    # the group isn't known, so it is a ?, which the hints and the search by name still work with
    return ("?:" + m.group(1), m.group(2)) if m else ("?:" + (base[:-4] if base.endswith(".jar") else base), "")
