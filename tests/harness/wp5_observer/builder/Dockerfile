FROM eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687

LABEL org.picketfence.wp5.phase="observer-build-only" \
      org.picketfence.wp5.owner="wp5-luna"

USER root

# Keycloak's pinned source-build guide requires Git. Keep the base's official
# Ubuntu 26.04 repositories and normal apt signature verification; install no
# other requested package and preserve the exact added package versions.
RUN set -eu; \
    export LC_ALL=C; \
    mkdir -p /usr/local/share; \
    dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > /tmp/wp5-packages-before; \
    timeout --signal=TERM --kill-after=30s 10m apt-get update >/dev/null 2>&1; \
    DEBIAN_FRONTEND=noninteractive timeout --signal=TERM --kill-after=30s 10m \
      apt-get install -y --no-install-recommends git >/dev/null 2>&1; \
    dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > /tmp/wp5-packages-after; \
    LC_ALL=C comm -13 /tmp/wp5-packages-before /tmp/wp5-packages-after \
      > /usr/local/share/wp5-added-package-versions.txt; \
    test -s /usr/local/share/wp5-added-package-versions.txt; \
    rm -f /tmp/wp5-packages-before /tmp/wp5-packages-after; \
    rm -rf /var/lib/apt/lists/*
