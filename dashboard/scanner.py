"""The assistant's way of looking at a project, read only and inside one folder.

The person sets a folder, and the assistant can list it, read files in it and search it, which is how it finds how the application starts running
and which packages are its own. What it reads goes to the model, so there are limits. It never leaves the folder, not by .. and not by a symbolic
link. It never reads a file that can hold credentials, like .env files, private keys and keystores. It skips what is built or fetched rather than
written, like target and node_modules, and files that are not text. And there is a limit on how much it reads in one turn.

list_libraries, search_libraries and describe_class look at what the application's libraries can do, which its own code doesn't say. They are in
libraries.py and read jar names and the public methods of a class, never the paths of the jars.

find_entry_candidates is the exception to reading one file at a time. It looks for the signals of how Java applications start running, servlets,
Spring and JAX-RS annotations, schedulers, listeners and main methods, and answers with where it found each, so the model can start from what
the project says and read only what it needs to decide.
"""

import fnmatch
import os
import re
import time

import libraries

MAX_LIST = 300                   # entries of one listing
MAX_READ_LINES = 400             # lines of one read
MAX_READ_CHARS = 40000           # characters of one read
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SEARCH_BYTES = 1024 * 1024   # a larger file isn't searched
MAX_MATCHES = 60
MAX_FILES_VISITED = 20000
TURN_BUDGET = 3 * 1024 * 1024    # characters sent to the model from the project in one turn
SEARCH_SECONDS = 15

# what is built or fetched and not written, which is not the project
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "target", "build", "dist", "out", ".idea", ".vscode", ".gradle", ".mvn", "venv", ".venv",
             "__pycache__", ".tox", ".cache", "bower_components", ".next", "coverage", ".settings", ".metadata"}
# directories that hold credentials, which are never entered
SECRET_DIRS = {".aws", ".ssh", ".gnupg", ".azure", ".kube"}
# files that can hold credentials, which are never read
SECRET_FILES = (".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
                "credentials", "credentials.*", ".netrc", "_netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials", "secrets", "secrets.*", "*.secret", "*.secrets",
                "*.ppk", "*.crt.key", "htpasswd", ".htpasswd")

TEXT_HINT = {"java", "kt", "kts", "scala", "groovy", "xml", "properties", "yaml", "yml", "json", "gradle", "md", "txt", "jsp", "jspx", "tag", "html", "js", "ts",
             "py", "go", "cs", "rb", "php", "sh", "toml", "cfg", "conf", "ini", "sql", "jot"}

BUILD_FILES = {"pom.xml": "Maven", "build.gradle": "Gradle", "build.gradle.kts": "Gradle", "settings.gradle": "Gradle", "package.json": "npm",
               "requirements.txt": "pip", "pyproject.toml": "Python", "go.mod": "Go", "Cargo.toml": "Cargo", "web.xml": "a servlet deployment descriptor",
               "application.properties": "Spring Boot", "application.yml": "Spring Boot", "application.yaml": "Spring Boot", "Dockerfile": "Docker",
               "build.xml": "Ant", "Procfile": "a Procfile"}

# how Java applications start running, as the lines that say so. The kind is what the model is told, and the first column what it looks for
SIGNALS = [
    (r"\bextends\s+(?:\w+\.)*HttpServlet\b|\bextends\s+(?:\w+\.)*GenericServlet\b", "a servlet class"),
    (r"@WebServlet\b", "a servlet annotation"),
    (r"\bimplements\s+(?:[\w.,\s]*\b)?(?:javax|jakarta)?\.?(?:servlet\.)?Filter\b|@WebFilter\b", "a servlet filter"),
    (r"@RestController\b|@Controller\b", "a Spring controller"),
    (r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\b", "a Spring request mapping"),
    (r"@Scheduled\b", "a Spring scheduled task"),
    (r"@(?:Kafka|Jms|Rabbit|Sqs|Stream)Listener\b|@(?:Incoming|Outgoing)\b", "a message listener"),
    (r"@EventListener\b|@RabbitHandler\b", "an event listener"),
    (r"@Path\(|@(?:GET|POST|PUT|DELETE)\b", "a JAX-RS resource"),
    (r"@(?:Route|Get|Post)\(\"|@Controller\(\"/", "a framework route"),
    (r"\bimplements\s+(?:\w+\.)*RequestHandler\b|\bimplements\s+(?:\w+\.)*RequestStreamHandler\b", "a Lambda handler"),
    (r"public\s+static\s+void\s+main\s*\(\s*(?:final\s+)?String\s*(?:\[\s*\]|\.\.\.)", "a main method"),
    (r"@SpringBootApplication\b", "a Spring Boot application class"),
    (r"extends\s+(?:\w+\.)*(?:Action|ActionSupport|DispatchAction)\b", "a Struts action"),
    (r"@MessageMapping\b|@ServerEndpoint\b|@OnMessage\b", "a websocket endpoint"),
    (r"\bBindableService\b|extends\s+\w+Grpc\.\w+ImplBase\b", "a gRPC service"),
    (r"@Tool\b|@McpTool\b", "a tool the model can call"),
    (r"\bimplements\s+(?:\w+\.)*Job\b|extends\s+(?:\w+\.)*QuartzJobBean\b", "a scheduled job"),
]
_SIGNALS = [(re.compile(rx), kind) for rx, kind in SIGNALS]
_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)


class ScanError(ValueError):
    """Something the assistant asked for that is not allowed or not there, which is said to it so it can ask for something else."""


def _secret_name(name):
    lowered = name.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in SECRET_FILES)


class Scanner:
    def __init__(self, app, local=True):
        self.app = app
        self.local = local               # a dashboard that other machines can reach must not read files of the one it runs on
        self.root = None
        self.spent = 0                   # characters sent to the model from the project this turn
        self._load()

    # ------------------------------------------------------------------ the folder

    def _load(self):
        import sqlite3
        try:
            db = sqlite3.connect(self.app.db_path)
            try:
                row = db.execute("SELECT value FROM settings WHERE key = 'project_folder'").fetchone()
            finally:
                db.close()
        except sqlite3.Error:
            row = None
        if row and os.path.isdir(row[0]):
            self.root = row[0]

    def set_root(self, path):
        """Sets the folder the assistant may look in, or clears it with an empty path. It has to be a directory that is there. The root of the
        disk and a person's whole home folder are refused, since what is wanted is a project and not everything they have."""
        if not self.local:
            raise ScanError("this dashboard can be reached from other machines, so it doesn't read the files of the one it runs on")
        import sqlite3
        path = (path or "").strip()
        if not path:
            real = None
        else:
            real = os.path.realpath(os.path.expanduser(path))
            if not os.path.isdir(real):
                raise ScanError("%s isn't a folder that is there" % path)
            if real == os.path.realpath(os.sep) or real == os.path.realpath(os.path.expanduser("~")):
                raise ScanError("that is too much to look in, choose the folder of a project")
        db = sqlite3.connect(self.app.db_path)
        try:
            if real:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('project_folder', ?)", (real,))
            else:
                db.execute("DELETE FROM settings WHERE key = 'project_folder'")
            db.commit()
        finally:
            db.close()
        self.root = real
        return real

    def begin(self):
        """A new turn, with all of the budget for reading."""
        self.spent = 0

    # ------------------------------------------------------------------ the tools the model is offered

    def tools(self):
        if not self.root or not self.local:
            return []
        path = {"type": "string", "description": "relative to the project folder, '.' being the folder"}
        return [
            {"name": "project_overview",
             "description": "A first look at the project folder. The build files found, the file counts by kind, the top level folders, and the Java packages "
                            "with how many files each has. Start here.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "find_entry_candidates",
             "description": "Looks through the project's source for the signals of how an application starts running, servlets and filters, Spring and JAX-RS "
                            "annotations, schedulers, message listeners, main methods and the like. Answers with where each was found, and the packages "
                            "the matching files are in, which are good candidates for the application's own packages. A starting point, you decide what is an "
                            "entry point.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "list_files",
             "description": "The files and folders in a folder of the project. Folders end with /. Built and fetched folders like target and node_modules, "
                            "and files that can hold credentials, are not shown.",
             "input_schema": {"type": "object", "properties": {"path": path}, "required": ["path"]}},
            {"name": "read_file",
             "description": "A file of the project as text, with line numbers, up to %d lines at a time. Say where to start to read further. Files that can hold "
                            "credentials, like .env files and keys, and files that are not text can't be read." % MAX_READ_LINES,
             "input_schema": {"type": "object", "properties": {"path": path, "start": {"type": "integer", "description": "the first line, 1 by default"},
                                                                  "lines": {"type": "integer", "description": "how many lines, up to %d" % MAX_READ_LINES}}, "required": ["path"]}},
            {"name": "search_files",
             "description": "Searches the text files of the project for a regular expression, a line at a time, and gives up to %d matches with the file and line. "
                            "glob limits it to files like *.java." % MAX_MATCHES,
             "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": path, "glob": {"type": "string"},
                                                                  "ignore_case": {"type": "boolean"}}, "required": ["pattern"]}},
            {"name": "list_libraries",
             "description": "The libraries the application has, from its build files, the jars it ships and the local build caches. Declared ones, the ones those need in "
                            "turn, and the ones built into a jar, as group:artifact:version. Also the application server and framework, and the libraries and platform "
                            "calls that are worth a look because of what they can do, each with the methods to start from. This is how to find what the application can do "
                            "that its own code doesn't say, like parsing XML, evaluating expressions, deserializing, fetching URLs or running scripts, which a library "
                            "or the server may do for it. Call it after the entry points.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "search_libraries",
             "description": "Finds classes by a regular expression on their full name, in the jars of the project's libraries, like 'Deserializ|ObjectInput' or "
                            "'(Template|Engine)$'. library narrows it to one, as group:artifact or part of its name. Use it to find the related capabilities of a library "
                            "beyond the ones list_libraries mentions.",
             "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "library": {"type": "string"}}, "required": ["pattern"]}},
            {"name": "describe_class",
             "description": "The public methods and fields of a class, so you can pick the method to watch and write its full name and parameters. It looks in the "
                            "project's libraries, and in the JDK for java, javax and jdk classes. It needs javap, which comes with the JDK.",
             "input_schema": {"type": "object", "properties": {"class_name": {"type": "string", "description": "with its package, like org.yaml.snakeyaml.Yaml"},
                                                                  "library": {"type": "string"}}, "required": ["class_name"]}},
        ]

    def functions(self):
        if not self.root or not self.local:
            return {}
        return {"project_overview": self.project_overview, "find_entry_candidates": self.find_entry_candidates, "list_files": self.list_files,
                "read_file": self.read_file, "search_files": self.search_files, "list_libraries": self.list_libraries,
                "search_libraries": self.search_libraries, "describe_class": self.describe_class}

    def describe(self, name, args, out):
        """What the page says about a tool call, so the person can see what is being looked at."""
        if "error" in out:
            return "Couldn't look at %s, %s" % (args.get("path") or args.get("pattern") or "the project", out["error"])
        if name == "project_overview":
            return "Looked over the project folder"
        if name == "find_entry_candidates":
            return "Looked for how the application starts, found %d signals in %d files" % (len(out.get("signals", [])), len({s["file"] for s in out.get("signals", [])}))
        if name == "list_files":
            return "Listed %s" % (out.get("path") or ".")
        if name == "read_file":
            return "Read %s, lines %d to %d" % (out["path"], out["start"], out["end"])
        if name == "search_files":
            return "Searched for %s, %d matches in %d files" % (args.get("pattern"), len(out["matches"]), len({m["file"] for m in out["matches"]}))
        if name == "list_libraries":
            return "Looked at the libraries, found %d" % (len(out.get("declared", [])) + len(out.get("needed_by_those", [])) + len(out.get("shipped", [])))
        if name == "search_libraries":
            return "Searched the libraries for %s, %d classes" % (args.get("pattern"), len(out["matches"]))
        if name == "describe_class":
            return "Looked at the methods of %s" % args.get("class_name")
        return name

    # ------------------------------------------------------------------ keeping inside the folder

    def _resolve(self, path):
        """The real path of something in the project, or a ScanError. Nothing outside the folder is reachable, whatever the path says and whatever
        links it goes through, and nothing that can hold credentials."""
        if not self.root:
            raise ScanError("no project folder is set")
        path = (path or ".").strip() or "."
        if os.path.isabs(path):
            raise ScanError("%s is outside the project folder, give a path relative to it" % path)
        root = self.root
        full = os.path.realpath(os.path.join(root, path))
        if full != root and not full.startswith(root + os.sep):
            raise ScanError("%s is outside the project folder" % path)
        parts = os.path.relpath(full, root).split(os.sep)
        for part in parts:
            if part in SECRET_DIRS or (part != "." and _secret_name(part)):
                raise ScanError("%s can hold credentials, so it isn't read" % path)
        return full

    def _rel(self, full):
        return os.path.relpath(full, self.root or os.sep).replace(os.sep, "/")

    def _spend(self, text):
        self.spent += len(text)
        if self.spent > TURN_BUDGET:
            raise ScanError("enough of the project has been read in this turn, work from what you have and say what else would help")

    def _is_text(self, full):
        try:
            with open(full, "rb") as fh:
                return b"\0" not in fh.read(4096)
        except OSError:
            return False

    def _inside(self, real):
        return self.root is not None and (real == self.root or real.startswith(self.root + os.sep))

    def _walk(self, base):
        """The text files under base, in order, leaving out what is built and what can hold credentials, and never following a link out of the folder."""
        visited = 0
        stack = [base]
        while stack:
            here = stack.pop()
            try:
                entries = sorted(os.scandir(here), key=lambda e: e.name)
            except OSError:
                continue
            dirs = []
            for entry in entries:
                if entry.name in SKIP_DIRS or entry.name in SECRET_DIRS or _secret_name(entry.name):
                    continue
                real = os.path.realpath(entry.path)
                if not self._inside(real):
                    continue
                if entry.is_dir(follow_symlinks=True):
                    dirs.append(real)
                elif entry.is_file(follow_symlinks=True):
                    visited += 1
                    if visited > MAX_FILES_VISITED:
                        return
                    yield real
            stack.extend(reversed(dirs))

    # ------------------------------------------------------------------ the libraries

    def _libraries(self, fresh=False):
        """The project's libraries, found again when asked and otherwise kept for the folder they were found in."""
        if not self.root:
            raise ScanError("no project folder is set")
        have = getattr(self, "_libs", None)
        if fresh or not have or have.root != self.root:
            self._libs = libraries.Libraries(self.root)
        return self._libs

    def list_libraries(self):
        out = self._libraries(fresh=True).listing()
        self._spend(str(out))
        return out

    def search_libraries(self, pattern, library=None):
        if not (pattern or "").strip():
            raise ScanError("give a pattern for the class names")
        out = self._libraries().search(pattern, library)
        self._spend(str(out))
        return out

    def describe_class(self, class_name, library=None):
        out = self._libraries().describe(class_name, library)
        self._spend(out["declaration"])
        return out

    # ------------------------------------------------------------------ the tools

    def list_files(self, path="."):
        full = self._resolve(path)
        if not os.path.isdir(full):
            raise ScanError("%s is not a folder" % path)
        entries, skipped = [], 0
        for entry in sorted(os.scandir(full), key=lambda e: (not e.is_dir(), e.name)):
            if _secret_name(entry.name) or entry.name in SECRET_DIRS:
                skipped += 1
                continue
            if entry.name in SKIP_DIRS:
                continue
            real = os.path.realpath(entry.path)
            if not self._inside(real):
                continue
            if entry.is_dir():
                entries.append({"name": entry.name + "/"})
            else:
                try:
                    entries.append({"name": entry.name, "bytes": entry.stat().st_size})
                except OSError:
                    continue
        truncated = len(entries) > MAX_LIST
        out = {"path": self._rel(full), "entries": entries[:MAX_LIST], "truncated": truncated, "left_out_as_credentials": skipped}
        self._spend(str(out))
        return out

    def read_file(self, path, start=1, lines=MAX_READ_LINES):
        full = self._resolve(path)
        if os.path.isdir(full):
            raise ScanError("%s is a folder, list it instead" % path)
        if not os.path.isfile(full):
            raise ScanError("%s isn't there" % path)
        if os.path.getsize(full) > MAX_FILE_BYTES:
            raise ScanError("%s is too large to read, search it instead" % path)
        if not self._is_text(full):
            raise ScanError("%s isn't a text file" % path)
        start = max(1, int(start or 1))
        count = max(1, min(int(lines or MAX_READ_LINES), MAX_READ_LINES))
        with open(full, encoding="utf-8", errors="replace") as fh:
            everything = fh.read().split("\n")
        total = len(everything) - (1 if everything and everything[-1] == "" else 0)
        chosen = everything[start - 1:start - 1 + count]
        text, used = [], 0
        for i, line in enumerate(chosen):
            row = "%d\t%s" % (start + i, line[:1000])
            if used + len(row) > MAX_READ_CHARS:
                break
            text.append(row)
            used += len(row) + 1
        end = start + len(text) - 1 if text else start
        out = {"path": self._rel(full), "start": start, "end": end, "total_lines": total, "text": "\n".join(text), "more": end < total}
        self._spend(out["text"])
        return out

    def search_files(self, pattern, path=".", glob=None, ignore_case=False):
        if not pattern or len(pattern) > 300:
            raise ScanError("give a pattern of up to 300 characters")
        try:
            rx = re.compile(pattern, re.I if ignore_case else 0)
        except re.error as e:
            raise ScanError("the pattern isn't a regular expression, %s" % e)
        base = self._resolve(path)
        files = [base] if os.path.isfile(base) else self._walk(base)
        matches, scanned, deadline, more = [], 0, time.monotonic() + SEARCH_SECONDS, False
        for f in files:
            if glob and not fnmatch.fnmatch(os.path.basename(f), glob):
                continue
            try:
                if os.path.getsize(f) > MAX_SEARCH_BYTES or not self._is_text(f):
                    continue
                with open(f, encoding="utf-8", errors="replace") as fh:
                    scanned += 1
                    for number, line in enumerate(fh, 1):
                        if rx.search(line[:2000]):
                            if len(matches) >= MAX_MATCHES:
                                more = True
                                break
                            matches.append({"file": self._rel(f), "line": number, "text": line.strip()[:200]})
            except OSError:
                continue
            if more or time.monotonic() > deadline:
                more = more or time.monotonic() > deadline
                break
        out = {"matches": matches, "files_searched": scanned, "more": more}
        self._spend(str(matches))
        return out

    def project_overview(self):
        base = self._resolve(".")
        kinds, builds, packages, total = {}, [], {}, 0
        for f in self._walk(base):
            total += 1
            name = os.path.basename(f)
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else name
            kinds[ext] = kinds.get(ext, 0) + 1
            if name in BUILD_FILES:
                builds.append({"file": self._rel(f), "is": BUILD_FILES[name]})
            if name.endswith(".java"):
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        head = fh.read(3000)
                except OSError:
                    continue
                found = _PACKAGE.search(head)
                if found:
                    prefix = ".".join(found.group(1).split(".")[:3])
                    packages[prefix] = packages.get(prefix, 0) + 1
        top = []
        for entry in sorted(os.scandir(base), key=lambda e: e.name):
            if entry.is_dir() and entry.name not in SKIP_DIRS and entry.name not in SECRET_DIRS:
                top.append(entry.name + "/")
        out = {"files": total, "by_kind": dict(sorted(kinds.items(), key=lambda kv: -kv[1])[:15]), "build_files": builds[:20], "top_level": top[:40],
               "java_packages": [{"package": p, "files": n} for p, n in sorted(packages.items(), key=lambda kv: -kv[1])[:20]]}
        self._spend(str(out))
        return out

    def find_entry_candidates(self):
        base = self._resolve(".")
        signals, packages, files = [], {}, 0
        deadline = time.monotonic() + SEARCH_SECONDS
        for f in self._walk(base):
            if not f.endswith((".java", ".kt", ".scala", ".groovy")):
                continue
            files += 1
            if time.monotonic() > deadline:
                break
            try:
                if os.path.getsize(f) > MAX_SEARCH_BYTES:
                    continue
                with open(f, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            found = []
            for number, line in enumerate(text.split("\n"), 1):
                for rx, kind in _SIGNALS:
                    if rx.search(line):
                        found.append({"kind": kind, "file": self._rel(f), "line": number, "text": line.strip()[:160]})
                        break
            if found:
                pkg = _PACKAGE.search(text[:3000])
                if pkg:
                    prefix = ".".join(pkg.group(1).split(".")[:3])
                    packages[prefix] = packages.get(prefix, 0) + 1
                signals.extend(found[:6])      # a few of a file are enough to see what it is, a controller doesn't need every mapping
        web = [self._rel(f) for f in self._walk(base) if os.path.basename(f) == "web.xml"][:5]
        jsp = sum(1 for f in self._walk(base) if f.endswith((".jsp", ".jspx")))
        signals = signals[:150]
        out = {"signals": signals, "kinds": sorted({s["kind"] for s in signals}), "candidate_packages": [{"package": p, "files_with_signals": n} for p, n in sorted(packages.items(), key=lambda kv: -kv[1])[:10]],
               "web_xml": web, "jsp_pages": jsp, "source_files_looked_at": files, "more": len(signals) >= 150}
        self._spend(str(out))
        return out
