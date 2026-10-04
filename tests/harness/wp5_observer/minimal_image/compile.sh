#!/usr/bin/env bash
set -euo pipefail

case "$(javac --version 2>/dev/null)" in
  "javac 21."*) ;;
  *) exit 41 ;;
esac

cd /upstream-lib
sha256sum -c /input/published-classpath.sha256 >/dev/null
test "$(wc -l < /input/published-classpath.sha256 | tr -d ' ')" = 471
awk '{print $2}' /input/published-classpath.sha256 | LC_ALL=C sort > /tmp/expected-jars
find . -type f -name '*.jar' -print | sed 's#^./##' | LC_ALL=C sort > /tmp/actual-jars
cmp /tmp/expected-jars /tmp/actual-jars
runtime=/upstream-lib/lib/main/org.keycloak.keycloak-quarkus-server-26.7.4.jar
test "$(sha256sum "$runtime" | cut -d ' ' -f1)" = 57bda3c01502dc553029f2e96f3b7b79e6e3aefcc33be13f67b0b29a3e693a2c

cd /input
sha256sum -c input.sha256 >/dev/null
mkdir -p /classes /tmp/original /tmp/updated
classpath="$(find /upstream-lib -type f -name '*.jar' -print | LC_ALL=C sort | paste -sd: -)"
test -n "$classpath"
timeout --signal=TERM --kill-after=30s 10m javac --release 17 -proc:none -classpath "$classpath" -d /classes \
  TransactionalSessionHandler.java AsPeerObserver.java
test "$(find /classes -type f -name '*.class' | wc -l | tr -d ' ')" = 2

handler=org/keycloak/quarkus/runtime/integration/resteasy/TransactionalSessionHandler.class
helper=org/keycloak/quarkus/runtime/integration/resteasy/AsPeerObserver.class
jar tf "$runtime" | LC_ALL=C sort > /tmp/original.entries
test "$(grep -Fxc "$handler" /tmp/original.entries)" = 1
if grep -Fqx "$helper" /tmp/original.entries; then
  exit 42
fi
cp "$runtime" /tmp/patched-runtime.jar
(cd /classes && jar --update --file /tmp/patched-runtime.jar "$handler" "$helper")
jar tf /tmp/patched-runtime.jar | LC_ALL=C sort > /tmp/updated.entries
{ cat /tmp/original.entries; printf '%s\n' "$helper"; } | LC_ALL=C sort > /tmp/expected.entries
cmp /tmp/expected.entries /tmp/updated.entries
(cd /tmp/original && jar xf "$runtime")
(cd /tmp/updated && jar xf /tmp/patched-runtime.jar)
while IFS= read -r entry; do
  test "$entry" = "$handler" && continue
  test -d "/tmp/original/$entry" && continue
  cmp "/tmp/original/$entry" "/tmp/updated/$entry"
done < /tmp/original.entries

javap -p -s -classpath "$runtime" org.keycloak.quarkus.runtime.integration.resteasy.TransactionalSessionHandler > /tmp/abi.before
javap -p -s -classpath /tmp/patched-runtime.jar org.keycloak.quarkus.runtime.integration.resteasy.TransactionalSessionHandler > /tmp/abi.after
cmp /tmp/abi.before /tmp/abi.after
javap -c -p -classpath /tmp/patched-runtime.jar org.keycloak.quarkus.runtime.integration.resteasy.TransactionalSessionHandler > /tmp/hook.disassembly
session_line="$(grep -n 'KeycloakSessionUtil.setKeycloakSession' /tmp/hook.disassembly | cut -d: -f1)"
hook_line="$(grep -n 'AsPeerObserver.observe' /tmp/hook.disassembly | cut -d: -f1)"
super_line="$(grep -n 'InvocationHandler.handle' /tmp/hook.disassembly | cut -d: -f1)"
test -n "$session_line" && test -n "$hook_line" && test -n "$super_line"
test "$(grep -c 'AsPeerObserver.observe' /tmp/hook.disassembly)" = 1
test "$session_line" -lt "$hook_line" && test "$hook_line" -lt "$super_line"
install -m 0644 /tmp/patched-runtime.jar /patched-runtime.jar
