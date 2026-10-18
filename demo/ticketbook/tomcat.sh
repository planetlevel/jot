# Sourced by run.sh and build.sh. Sets CATALINA_HOME, downloading Tomcat into target/ on first use and checking it against
# Apache's SHA-512. To use an install you already have, set CATALINA_HOME. HERE must be this directory.
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
