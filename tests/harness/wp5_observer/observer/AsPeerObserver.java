/*
 * Copyright 2026 Picketfence Labs.
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.quarkus.runtime.integration.resteasy;

import java.io.InputStream;
import java.time.Instant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.ws.rs.core.HttpHeaders;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.http.HttpRequest;
import io.vertx.ext.web.RoutingContext;

/** Test-only observer for the isolated AS-MTLS-OBS-01 fixture. */
final class AsPeerObserver {
    private static final Logger LOG = Logger.getLogger(AsPeerObserver.class);
    private static final String ENABLED_ENV = "FAPI_DEMO_AS_PEER_OBSERVER";
    private static final String CA_FILE_ENV = "FAPI_DEMO_AS_PEER_CA_FILE";
    private static final String CORRELATION_HEADER = "X-Fapi-Demo-Observation-ID";
    private static final String REQUEST_MARKER = AsPeerObserver.class.getName() + ".seen";
    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";
    private static final Pattern CORRELATION_ID = Pattern.compile("[0-9a-f]{32}");

    private AsPeerObserver() {
    }

    static void observe(KeycloakSession session) {
        // Keep this check first. OFF mode must not inspect request, headers, or TLS peer state.
        if (!"true".equals(System.getenv(ENABLED_ENV))) {
            return;
        }

        RoutingContext routingContext;
        try {
            Instance<RoutingContext> instances = CDI.current().select(RoutingContext.class);
            if (!instances.isResolvable()) {
                emit("none", "unknown", "unknown", "unknown", false, 0, false, false, false,
                        "no_request_context", "none");
                return;
            }
            routingContext = instances.get();
        } catch (RuntimeException ignored) {
            emit("none", "unknown", "unknown", "unknown", false, 0, false, false, false,
                    "request_context_unavailable", "none");
            return;
        }

        try {
            if (Boolean.TRUE.equals(routingContext.get(REQUEST_MARKER))) {
                return;
            }
            // Mark before any request processing so sub-resource handler invocations cannot duplicate it.
            routingContext.put(REQUEST_MARKER, Boolean.TRUE);
        } catch (RuntimeException ignored) {
            emit("none", "unknown", "unknown", "unknown", false, 0, false, false, false,
                    "request_marker_unavailable", "none");
            return;
        }

        String observedMethod = "unknown";
        String observedPath = "unknown";
        String endpoint = "unknown";
        String correlation = "none";
        try {
            HttpRequest request = session.getContext().getHttpRequest();
            if (request == null) {
                emit(correlation, endpoint, observedMethod, observedPath, false, 0, false, false, false,
                        "request_unavailable", "none");
                return;
            }

            String candidateMethod = request.getHttpMethod();
            String candidatePath = canonicalPath(routingContext.request().path());
            if (candidatePath == null) {
                return;
            }
            String candidateEndpoint = endpoint(candidateMethod, candidatePath);
            if (candidateEndpoint == null) {
                return;
            }
            // Retain only values matched to the fixed inventory, never arbitrary URI metadata.
            observedMethod = candidateMethod;
            observedPath = candidatePath;
            endpoint = candidateEndpoint;

            correlation = correlationId(request.getHttpHeaders());
            if (correlation == null) {
                emit("none", endpoint, observedMethod, observedPath, false, 0, false, false, false,
                        "correlation_invalid", "none");
                return;
            }

            X509Certificate[] chain = request.getClientCertificateChain();
            if (chain == null || chain.length == 0 || chain[0] == null) {
                emit(correlation, endpoint, observedMethod, observedPath, false, 0, false, false, false,
                        "peer_absent", "none");
                return;
            }

            X509Certificate leaf = chain[0];
            String thumbprint = sha256Url(leaf.getEncoded());
            boolean validNow = validAtCurrentTime(chain);
            boolean clientAuthEku = hasClientAuthEku(leaf);
            boolean pkix = validatesToFixtureCa(chain);
            emit(correlation, endpoint, observedMethod, observedPath, true, chain.length, pkix, validNow, clientAuthEku,
                    pkix && validNow && clientAuthEku ? "none" : "peer_validation_failed", thumbprint);
        } catch (Exception ignored) {
            // Never serialize an exception message, request value, certificate, or stack trace.
            emit(correlation, endpoint, observedMethod, observedPath, false, 0, false, false, false,
                    "observer_failure", "none");
        }
    }

    static String canonicalPath(String absoluteRawPath) {
        if ("/realms/fapi-demo/.well-known/openid-configuration".equals(absoluteRawPath)) {
            return "realms/fapi-demo/.well-known/openid-configuration";
        }
        if ("/realms/fapi-demo/protocol/openid-connect/certs".equals(absoluteRawPath)) {
            return "realms/fapi-demo/protocol/openid-connect/certs";
        }
        if ("/realms/fapi-demo/protocol/openid-connect/ext/par/request".equals(absoluteRawPath)) {
            return "realms/fapi-demo/protocol/openid-connect/ext/par/request";
        }
        if ("/realms/fapi-demo/protocol/openid-connect/token".equals(absoluteRawPath)) {
            return "realms/fapi-demo/protocol/openid-connect/token";
        }
        if ("/realms/fapi-demo/protocol/openid-connect/revoke".equals(absoluteRawPath)) {
            return "realms/fapi-demo/protocol/openid-connect/revoke";
        }
        return null;
    }

    static String endpoint(String method, String path) {
        if ("GET".equals(method) && "realms/fapi-demo/.well-known/openid-configuration".equals(path)) {
            return "discovery";
        }
        if ("GET".equals(method) && "realms/fapi-demo/protocol/openid-connect/certs".equals(path)) {
            return "jwks";
        }
        if ("POST".equals(method) && "realms/fapi-demo/protocol/openid-connect/ext/par/request".equals(path)) {
            return "par";
        }
        if ("POST".equals(method) && "realms/fapi-demo/protocol/openid-connect/token".equals(path)) {
            return "token";
        }
        if ("POST".equals(method) && "realms/fapi-demo/protocol/openid-connect/revoke".equals(path)) {
            return "revoke";
        }
        return null;
    }

    private static String correlationId(HttpHeaders headers) {
        List<String> values = headers.getRequestHeader(CORRELATION_HEADER);
        if (values == null || values.size() != 1) {
            return null;
        }
        String value = values.get(0);
        if (value == null || value.length() != 32 || !CORRELATION_ID.matcher(value).matches()) {
            return null;
        }
        return value;
    }

    private static boolean validAtCurrentTime(X509Certificate[] chain) {
        try {
            for (X509Certificate certificate : chain) {
                if (certificate == null) {
                    return false;
                }
                certificate.checkValidity();
            }
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean hasClientAuthEku(X509Certificate leaf) {
        try {
            List<String> eku = leaf.getExtendedKeyUsage();
            return eku != null && eku.contains(CLIENT_AUTH_EKU);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean validatesToFixtureCa(X509Certificate[] chain) {
        try {
            String caPath = System.getenv(CA_FILE_ENV);
            if (caPath == null || caPath.isBlank()) {
                return false;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate ca;
            try (InputStream input = Files.newInputStream(Path.of(caPath))) {
                ca = (X509Certificate) factory.generateCertificate(input);
            }

            List<X509Certificate> pathCertificates = new ArrayList<>();
            for (X509Certificate certificate : chain) {
                if (certificate == null) {
                    return false;
                }
                if (certificate.equals(ca)) {
                    break;
                }
                pathCertificates.add(certificate);
            }
            if (pathCertificates.isEmpty()) {
                return false;
            }

            CertPath certPath = factory.generateCertPath(pathCertificates);
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(ca, null)));
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(certPath, parameters);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static String sha256Url(byte[] certificateDer) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificateDer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static void emit(String correlation, String endpoint, String method, String path,
            boolean peerPresent, int chainCount, boolean pkix, boolean validNow, boolean clientAuthEku,
            String error, String thumbprint) {
        try {
            LOG.infof("WP5_AS_PEER_OBS v=1 observed_at=%s correlation_id=%s endpoint=%s method=%s path=%s peer_present=%s chain_count=%d pkix=%s valid_now=%s client_auth_eku=%s leaf_sha256=%s error=%s",
                    Instant.now().toString(), correlation, endpoint, method, path, peerPresent, chainCount,
                    pkix, validNow, clientAuthEku, thumbprint, error);
        } catch (RuntimeException ignored) {
            // An observer logging failure must not change Keycloak request handling.
        }
    }
}
