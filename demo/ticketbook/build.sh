#!/usr/bin/env bash
# Builds what webapp/WEB-INF needs for Tomcat 11 from pom.xml and src/main/java.
#   classes  src/main/java compiled for Java 17 and Jakarta EE 11, copied into WEB-INF/classes. The esapi/ resources
#            already there are left alone.
#   lib      the libraries in pom.xml, converted from javax to jakarta by Tomcat's migration tool, into WEB-INF/lib.
#            The libraries are deliberately old and vulnerable, see the note in pom.xml.
# Needs Maven and Java 17 or newer. Tomcat is downloaded into target/ on first use, see tomcat.sh.
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)
. ./tomcat.sh

# Not mvn clean, that would also delete the Tomcat that tomcat.sh keeps in target/
find target/classes -name '*.class' -delete 2>/dev/null || true
mvn -q -f pom.xml compile
mkdir -p webapp/WEB-INF/classes
find webapp/WEB-INF/classes/com/acme -name '*.class' -delete 2>/dev/null || true
cp -R target/classes/com webapp/WEB-INF/classes/

mvn -q -f pom.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
  -DincludeScope=runtime -DoutputDirectory="$HERE/target/lib-javax"
# Migrate into target/ first, so a failed migration leaves WEB-INF/lib as it was.
find target/lib-jakarta -name '*.jar' -delete 2>/dev/null || true
"$CATALINA_HOME/bin/migrate.sh" target/lib-javax target/lib-jakarta > target/migrate-lib.log 2>&1 \
  || { echo "Tomcat's migration tool failed, see demo/ticketbook/target/migrate-lib.log" >&2; exit 1; }
mkdir -p webapp/WEB-INF/lib
find webapp/WEB-INF/lib -name '*.jar' -delete
cp target/lib-jakarta/*.jar webapp/WEB-INF/lib/

echo "Built $(find webapp/WEB-INF/classes/com -name '*.class' | wc -l | tr -d ' ') classes and $(find webapp/WEB-INF/lib -name '*.jar' | wc -l | tr -d ' ') jars into webapp/WEB-INF"
