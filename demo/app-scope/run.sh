#!/usr/bin/env bash
# Shows that the application scope follows an annotation. A sensor with no scopes only fires inside the method that carries
# @Entry, one that says scopes: [] fires everywhere. Set JAR to use a jar other than target/jot-<version>.jar.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
JAR=${JAR:-$ROOT/target/jot-$(cd $ROOT && mvn -q help:evaluate -Dexpression=project.version -DforceStdout).jar}
[ -f "$JAR" ] || (cd $ROOT && mvn -q package -DskipTests)

OUT=target
mkdir -p $OUT
javac -d $OUT Demo.java
: > $OUT/events.jsonl
java -Djot.output=json -Djot.output.file=$OUT/events.jsonl -javaagent:$JAR=jot.yaml -cp $OUT Demo 2>/dev/null

count() { grep -c "\"sensor\":\"$1\"" $OUT/events.jsonl || true; }
in_app=$(count file-in-app); digests=$(count digest-in-app); anywhere=$(count file-anywhere); entries=$(count on-entry)
printf "  %-16s %s   (inside only, a call and a helper call, in each of two entries)\n" file-in-app "$in_app"
printf "  %-16s %s   (the SHA-256 inside, not the MD5 before)\n" digest-in-app "$digests"
printf "  %-16s %s   (also the startup and after calls)\n" file-anywhere "$anywhere"
printf "  %-16s %s   (a JOT on the entry point itself, once for each call)\n" on-entry "$entries"
[ "$in_app" = 4 ] && [ "$digests" = 2 ] && [ "$anywhere" = 6 ] && [ "$entries" = 2 ] && echo "PASS" || { echo "FAIL" >&2; exit 1; }
