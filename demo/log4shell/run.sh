#!/usr/bin/env bash
# Microsandbox demo for CVE-2021-44228 (Log4Shell) using a single JOT rule.
# Runs the same app with and without JOT. JNDI lookups stay allowed (they are a legitimate
# Log4j feature), but process execution is blocked while inside JndiLookup.lookup.
# The "malicious directory" is simulated by FakeDirectory, it is not a real LDAP exploit.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
JAR=$ROOT/target/jot-$(cd $ROOT && mvn -q help:evaluate -Dexpression=project.version -DforceStdout).jar
[ -f "$JAR" ] || (cd $ROOT && mvn -q package -DskipTests)

OUT=target
mkdir -p $OUT/lib $OUT/classes
for a in log4j-core log4j-api; do
  [ -f $OUT/lib/$a-2.14.1.jar ] || mvn -q dependency:copy -Dartifact=org.apache.logging.log4j:$a:2.14.1 -DoutputDirectory=$OUT/lib
done
CP=$OUT/classes:$OUT/lib/log4j-core-2.14.1.jar:$OUT/lib/log4j-api-2.14.1.jar
javac -cp "$CP" -d $OUT/classes FakeDirectory.java Victim.java

run() {
  rm -f pwned.txt
  java "$@" -Djava.naming.factory.initial=FakeDirectory -cp "$CP" Victim 2>&1 \
    | grep -E 'ERROR Victim|pwned|blocked|SEVERE'
  rm -f pwned.txt
}
echo "=== without JOT ==="; run
echo; echo "=== with JOT (log4shell.jot) ==="; run -Djot.verbose=true -javaagent:$JAR=log4shell.jot
