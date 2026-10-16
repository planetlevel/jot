#!/usr/bin/env bash
# Shows why a sensor on a class the JVM loads at startup, like java.io.File, never fires, and how
# -Djot.retransform=true fixes it. Runs the same program twice and counts what each sensor saw.
# Set JAR to use a jar other than target/jot-<version>.jar.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
JAR=${JAR:-$ROOT/target/jot-$(cd $ROOT && mvn -q help:evaluate -Dexpression=project.version -DforceStdout).jar}
[ -f "$JAR" ] || (cd $ROOT && mvn -q package -DskipTests)

OUT=target
mkdir -p $OUT
javac -d $OUT Demo.java

count() { grep -c "\"sensor\":\"$1\"" $OUT/events.jsonl || true; }
run() {
  : > $OUT/events.jsonl
  java "$@" -Djot.output=json -Djot.output.file=$OUT/events.jsonl -javaagent:$JAR=watch.jot -cp $OUT Demo 2>/dev/null
  printf "  %-18s %s\n" file-created "$(count file-created)" digest-requested "$(count digest-requested)" \
    process-created "$(count process-created)" cipher-requested "$(count cipher-requested)"
}
echo "=== default, classes loaded before the agent are not instrumented"; run
default_files=$(count file-created)
echo "=== -Djot.retransform=true"; run -Djot.retransform=true
retransformed_files=$(count file-created)

[ "$default_files" = 0 ] && [ "$retransformed_files" = 1 ] && [ "$(count digest-requested)" = 1 ] \
  && echo "PASS" || { echo "FAIL" >&2; exit 1; }
