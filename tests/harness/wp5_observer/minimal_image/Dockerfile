FROM quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c AS upstream

FROM eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687 AS compile
COPY --from=upstream /opt/keycloak/lib/ /upstream-lib/
COPY published-classpath.sha256 input.sha256 context-manifest.json compile.sh /input/
COPY TransactionalSessionHandler.java AsPeerObserver.java /input/
RUN /bin/bash /input/compile.sh

FROM quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c AS runtime
LABEL org.picketfence.wp5.owner="wp5-luna" org.picketfence.wp5.phase="observer-image-build-only"
COPY --from=compile --chown=1000:0 --chmod=0644 /patched-runtime.jar /opt/keycloak/lib/lib/main/org.keycloak.keycloak-quarkus-server-26.7.4.jar
