#!/usr/bin/env bash
# Runs the TicketBook demo app under Tomcat 11 with JOT attached, writing JSON events for the dashboard.
#
#   demo/ticketbook/run.sh            start Tomcat on port 8080, then browse http://localhost:8080/ticketbook
#   python3 dashboard/server.py --app com.acme --app org.apache.jsp --log jot-events.jsonl --jot demo/ticketbook/jots
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
cp "$HERE/conf/tomcat-users.xml" "$BASE/conf/tomcat-users.xml"   # the demo accounts, in place of the stock file
cat > "$BASE/conf/Catalina/localhost/ticketbook.xml" <<XML
<Context docBase="$HERE/webapp" reloadable="false"/>
XML

# The policy. jots/ holds the sensors that only observe, and rules/ the rules that can stop a call.
#   MODE=observe   (default) only the sensors, nothing can be blocked
#   MODE=enforce   the sensors and the rules, the rules block. The dashboard can switch them to report only
#   MODE=monitor   the sensors and the rules, but every rule only reports. The attacks still work. This is
#                  fixed for the life of the process, the dashboard can't switch it to block
MODE=${MODE:-observe}
case "$MODE" in observe|monitor|enforce) ;; *) echo "MODE must be observe, monitor or enforce" >&2; exit 1;; esac
ACTIVE=$HERE/target/active-jots
mkdir -p "$ACTIVE"
rm -f "$ACTIVE"/*.jot
cp "$HERE"/jots/*.jot "$ACTIVE"/
[ "$MODE" = observe ] || cp "$HERE"/rules/*.jot "$ACTIVE"/

# The file the dashboard writes to switch rules between monitor and block. Start from a clean one so a setting
# left over from an earlier session can't quietly change what this run does.
CONTROL=${JOT_CONTROL:-$ROOT/jot-control.json}
rm -f "$CONTROL"

LOG=${JOT_LOG:-$ROOT/jot-events.jsonl}
export CATALINA_BASE=$BASE
export CATALINA_HOME
ENFORCE_OPT=""
[ "$MODE" = monitor ] && ENFORCE_OPT="-Djot.enforce=false"
# Remove -Djot.verbose=true to quiet instrumentation errors.
export CATALINA_OPTS="-Djot.verbose=true -Djot.output=json -Djot.output.stack=500 -Djot.output.file=$LOG -Djot.app=ticketbook \
  -Djot.control=$CONTROL $ENFORCE_OPT -javaagent:$JAR=$ACTIVE"

echo "Mode $MODE. JOT events go to $LOG"
echo "Dashboard: python3 dashboard/server.py --app com.acme --app org.apache.jsp --log $LOG --jot jots --jot rules --control $CONTROL"
exec "$CATALINA_HOME/bin/catalina.sh" run
