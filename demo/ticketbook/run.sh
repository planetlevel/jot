#!/usr/bin/env bash
# Runs the TicketBook demo app under Tomcat 11 with JOT attached, writing JSON events for the dashboard.
#
#   demo/ticketbook/run.sh            start Tomcat on port 8080, then browse http://localhost:8080/ticketbook
#   python3 dashboard/server.py --log jot-events.jsonl --jot demo/ticketbook/jots
#
# Tomcat 11 is downloaded into demo/ticketbook/target on first use and checked against Apache's SHA-512.
# To use an install you already have, set CATALINA_HOME. Needs Java 17 or newer, found through JAVA_HOME or the PATH.
#
# TicketBook is served from demo/ticketbook/webapp, which must use jakarta.servlet. If there is a
# webapp.javax directory and no webapp, Tomcat's migration tool converts it.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
HERE=$(pwd)
TOMCAT_VERSION=${TOMCAT_VERSION:-11.0.27}

if [ -z "${CATALINA_HOME:-}" ]; then
  CATALINA_HOME=$HERE/target/apache-tomcat-$TOMCAT_VERSION
  if [ ! -x "$CATALINA_HOME/bin/catalina.sh" ]; then
    DL=$HERE/target/dl-tomcat-$TOMCAT_VERSION
    URL=https://archive.apache.org/dist/tomcat/tomcat-${TOMCAT_VERSION%%.*}/v$TOMCAT_VERSION/bin
    mkdir -p "$DL"
    echo "Downloading Tomcat $TOMCAT_VERSION from archive.apache.org"
    curl -sSfo "$DL/apache-tomcat-$TOMCAT_VERSION.tar.gz" "$URL/apache-tomcat-$TOMCAT_VERSION.tar.gz"
    curl -sSfo "$DL/apache-tomcat-$TOMCAT_VERSION.tar.gz.sha512" "$URL/apache-tomcat-$TOMCAT_VERSION.tar.gz.sha512"
    (cd "$DL" && shasum -a 512 -c "apache-tomcat-$TOMCAT_VERSION.tar.gz.sha512")
    tar -xzf "$DL/apache-tomcat-$TOMCAT_VERSION.tar.gz" -C "$HERE/target"
  fi
fi
[ -x "$CATALINA_HOME/bin/catalina.sh" ] || { echo "No Tomcat at $CATALINA_HOME" >&2; exit 1; }

if [ ! -d webapp ] && [ -d webapp.javax ]; then
  echo "Converting webapp.javax to jakarta.servlet"
  "$CATALINA_HOME/bin/migrate.sh" webapp.javax webapp > target/migrate.log 2>&1
fi
[ -d webapp ] || { echo "No demo/ticketbook/webapp to serve" >&2; exit 1; }

VERSION=$(cd "$ROOT" && mvn -q help:evaluate -Dexpression=project.version -DforceStdout)
JAR=$ROOT/target/jot-$VERSION.jar
[ -f "$JAR" ] || (cd "$ROOT" && mvn -q package -DskipTests)

# Tomcat itself is not modified, this script keeps its own CATALINA_BASE
BASE=$HERE/target/tomcat-base
mkdir -p "$BASE"/{logs,temp,work,webapps,conf/Catalina/localhost}
cp -R "$CATALINA_HOME/conf/." "$BASE/conf/"
cat > "$BASE/conf/Catalina/localhost/ticketbook.xml" <<XML
<Context docBase="$HERE/webapp" reloadable="false"/>
XML

LOG=${JOT_LOG:-$ROOT/jot-events.jsonl}
export CATALINA_BASE=$BASE
export CATALINA_HOME
# Observe-only sensors, nothing here blocks. Remove -Djot.verbose=true to quiet instrumentation errors.
export CATALINA_OPTS="-Djot.verbose=true -Djot.output=json -Djot.output.file=$LOG -Djot.app=ticketbook \
  -javaagent:$JAR=$HERE/jots"

echo "JOT events go to $LOG"
exec "$CATALINA_HOME/bin/catalina.sh" run
