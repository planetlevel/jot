#!/usr/bin/env bash
# Runs the TicketBook demo app under Tomcat 11 with JOT attached, writing JSON events for the dashboard.
#
#   demo/ticketbook/run.sh            start Tomcat on port 8080, then browse http://localhost:8080/ticketbook
#   cd demo/ticketbook && python3 ../../dashboard/server.py     the dashboard, which finds .jot/ on its own
#
# Tomcat 11 is downloaded into demo/ticketbook/target on first use, see tomcat.sh. To use an install you already have,
# set CATALINA_HOME. Needs Java 17 or newer, found through JAVA_HOME or the PATH.
#
# TicketBook is served from demo/ticketbook/webapp, which must use jakarta.servlet. build.sh makes its classes and libraries
# from src/ and pom.xml, and run.sh runs it when WEB-INF/lib has no jars. If there is a webapp.javax directory and no
# webapp, Tomcat's migration tool converts it.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
HERE=$(pwd)
. ./tomcat.sh

if [ ! -d webapp ] && [ -d webapp.javax ]; then
  echo "Converting webapp.javax to jakarta.servlet"
  "$CATALINA_HOME/bin/migrate.sh" webapp.javax webapp > target/migrate.log 2>&1
fi
[ -d webapp ] || { echo "No demo/ticketbook/webapp to serve" >&2; exit 1; }
if ! ls webapp/WEB-INF/lib/*.jar > /dev/null 2>&1; then
  echo "No libraries in webapp/WEB-INF/lib, running build.sh"
  ./build.sh
fi

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

# The configuration is .jot/jot.yaml, and what JOT writes while it runs goes in .jot/ too. It holds the sensors and the rules that can stop a call, and lists ../../cves, the CVE microsandboxes. Everything in it is always
# loaded. The agent and the dashboard both read that file. MODE is only the state the run starts in. The dashboard's Monitor and Protect toggle changes it while the
# app runs, nothing here locks it.
#   MODE=protect   (default) the rules stop the call
#   MODE=monitor   the rules only report what they would stop. The attacks still work
MODE=${MODE:-protect}
case "$MODE" in monitor|protect) ;; *) echo "MODE must be monitor or protect" >&2; exit 1;; esac

# The file the dashboard writes to switch rules between monitor and block. Start from a clean one so a setting
# left over from an earlier session can't quietly change what this run does.
mkdir -p "$HERE/.jot"
CONTROL=${JOT_CONTROL:-$HERE/.jot/control.yaml}
rm -f "$CONTROL"
[ "$MODE" = monitor ] && printf 'v: 1\nprotect: false\nsensors: {}\nby: run.sh\n' > "$CONTROL"

LOG=${JOT_LOG:-$HERE/.jot/events.jsonl}
export CATALINA_BASE=$BASE
export CATALINA_HOME
# The agent says nothing to the application's output. Its own log, for debugging it, is .jot/agent.log. Remove -Djot.log to stop it.
export CATALINA_OPTS="-Djot.verbose=true -Djot.log=$HERE/.jot/agent.log -Djot.output=json -Djot.output.stack=500 -Djot.output.file=$LOG -Djot.app=ticketbook \
  -Djot.control=$CONTROL -javaagent:$JAR=$HERE/.jot/jot.yaml"

echo "Mode $MODE. JOT events go to $LOG"
echo "Dashboard: cd demo/ticketbook && python3 ../../dashboard/server.py"
exec "$CATALINA_HOME/bin/catalina.sh" run
