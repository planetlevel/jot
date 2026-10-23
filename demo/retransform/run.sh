#!/usr/bin/env bash
# Shows that sensors on classes the JVM loads at startup, like java.io.File, fire by default, and that they
# never do with -Djot.retransform=false. Runs the same program twice and counts what each sensor saw.
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
  java "$@" -Djot.output=json -Djot.output.file=$OUT/events.jsonl -javaagent:$JAR=jot.yaml -cp $OUT Demo 2>/dev/null
  printf "  %-18s %s\n" file-created "$(count file-created)" file-path "$(count file-path)" digest-requested "$(count digest-requested)" \
    process-created "$(count process-created)" cipher-requested "$(count cipher-requested)"
}
echo "=== default, which also instruments classes the JVM loaded before the agent"; run
default_files=$(count file-created); default_path=$(count file-path); default_digest=$(count digest-requested)
echo "=== -Djot.retransform=false, those classes are never instrumented"; run -Djot.retransform=false
off_files=$(count file-created)

[ "$default_files" = 1 ] && [ "$default_path" = 1 ] && [ "$default_digest" = 1 ] && [ "$off_files" = 0 ] \
  && echo "PASS" || { echo "FAIL" >&2; exit 1; }
