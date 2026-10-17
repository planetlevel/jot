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
  out=$(java -Djot.verbose=true -javaagent:$JAR=jots-$kind.yaml -cp target ScopeLeak $kind 2>&1 | grep -E '^(PASS|FAIL)|SEVERE')
  echo "$out"
  echo "$out" | grep -qE '^FAIL|SEVERE' && fail=1
done
exit $fail
