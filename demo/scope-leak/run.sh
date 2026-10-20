#!/usr/bin/env bash
# Checks that a JOT scope is released when the scoped method or constructor throws,
# and that the sensor keeps blocking on later attempts. Every line should say PASS.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
JAR=$ROOT/target/jot-$(cd $ROOT && mvn -q help:evaluate -Dexpression=project.version -DforceStdout).jar
[ -f "$JAR" ] || (cd $ROOT && mvn -q package -DskipTests)
mkdir -p target && javac -d target ScopeLeak.java
fail=0
for kind in method ctor; do
  echo "=== scope on $kind ==="
  # the agent says nothing to the console, so its errors are read from its own log
  rm -f target/agent-$kind.log
  out=$(java -Djot.verbose=true -Djot.log=target/agent-$kind.log -javaagent:$JAR=jots-$kind.yaml -cp target ScopeLeak $kind 2>&1 | grep -E '^(PASS|FAIL)' || true)
  [ -f target/agent-$kind.log ] && out="$out"$'\n'"$(grep SEVERE target/agent-$kind.log || true)"
  echo "$out"
  echo "$out" | grep -qE '^FAIL|SEVERE' && fail=1
done
exit $fail
