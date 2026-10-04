"""Create the isolated request-local handler re-entry probe source variant."""

from __future__ import annotations

import hashlib


V3_HELPER_SHA256 = "550291bd8411ca4fa18c03709e7be730532a67bfc244ef4f6ab35cf73d540141"

_CONSTANT_ANCHOR = (
    b'    private static final String REQUEST_MARKER = AsPeerObserver.class.getName() + ".seen";\n'
    b'    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";\n'
)
_CONSTANT_REPLACEMENT = (
    b'    private static final String REQUEST_MARKER = AsPeerObserver.class.getName() + ".seen";\n'
    b'    private static final String REENTRY_ENABLED_ENV = "FAPI_DEMO_AS_PEER_REENTRY_PROBE";\n'
    b'    private static final String REENTRY_STATE = AsPeerObserver.class.getName() + ".reentry";\n'
    b'    private static final int MAX_REENTRY_COUNT = 16;\n'
    b'    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";\n'
)
_DUPLICATE_ANCHOR = (
    b'            if (Boolean.TRUE.equals(routingContext.get(REQUEST_MARKER))) {\n'
    b'                return;\n'
    b'            }\n'
)
_DUPLICATE_REPLACEMENT = (
    b'            if (Boolean.TRUE.equals(routingContext.get(REQUEST_MARKER))) {\n'
    b'                recordReentry(routingContext, reentryProbeEnabled);\n'
    b'                return;\n'
    b'            }\n'
)
_OFF_GUARD_ANCHOR = (
    b'        if (!"true".equals(System.getenv(ENABLED_ENV))) {\n'
    b'            return;\n'
    b'        }\n'
)
_OFF_GUARD_REPLACEMENT = (
    b'        if (!"true".equals(System.getenv(ENABLED_ENV))) {\n'
    b'            return;\n'
    b'        }\n'
    b'        // Probe mode is request-local and opt-in; the observer OFF guard above stays first.\n'
    b'        boolean reentryProbeEnabled = "true".equals(System.getenv(REENTRY_ENABLED_ENV));\n'
)
_CORRELATION_ANCHOR = (
    b'            if (correlation == null) {\n'
    b'                emit("none", endpoint, observedMethod, observedPath, false, 0, false, false, false,\n'
    b'                        "correlation_invalid", "none");\n'
    b'                return;\n'
    b'            }\n'
    b'\n'
    b'            X509Certificate[] chain = request.getClientCertificateChain();\n'
)
_CORRELATION_REPLACEMENT = (
    b'            if (correlation == null) {\n'
    b'                emit("none", endpoint, observedMethod, observedPath, false, 0, false, false, false,\n'
    b'                        "correlation_invalid", "none");\n'
    b'                return;\n'
    b'            }\n'
    b'\n'
    b'            if (reentryProbeEnabled) {\n'
    b'                try {\n'
    b'                    routingContext.put(REENTRY_STATE, new String[] {correlation, endpoint, observedMethod, observedPath, "1", "false"});\n'
    b'                } catch (RuntimeException ignored) {\n'
    b'                    // Missing diagnostic state must not change observer or request behavior.\n'
    b'                }\n'
    b'            }\n'
    b'\n'
    b'            X509Certificate[] chain = request.getClientCertificateChain();\n'
)
_METHOD_ANCHOR = b'    static String canonicalPath(String absoluteRawPath) {\n'
_METHOD_INSERT = b'''    private static void recordReentry(RoutingContext routingContext, boolean reentryProbeEnabled) {
        if (!reentryProbeEnabled) {
            return;
        }
        try {
            Object stored = routingContext.get(REENTRY_STATE);
            if (!(stored instanceof String[] state) || state.length != 6 || "true".equals(state[5])) {
                return;
            }

            int count;
            try {
                count = Integer.parseInt(state[4]);
            } catch (NumberFormatException ignored) {
                return;
            }
            if (count < 1 || count > MAX_REENTRY_COUNT) {
                return;
            }
            if (count == MAX_REENTRY_COUNT) {
                state[5] = "true";
                emitReentry(state, count, true);
                return;
            }

            count++;
            state[4] = Integer.toString(count);
            emitReentry(state, count, false);
        } catch (RuntimeException ignored) {
            // Probe failures must not escape into the observer's existing marker handling.
        }
    }

    private static void emitReentry(String[] state, int count, boolean overflow) {
        try {
            if (overflow) {
                LOG.infof("WP5_AS_PEER_REENTRY v=1 error=count_limit_exceeded correlation_id=%s endpoint=%s method=%s path=%s count=%d",
                        state[0], state[1], state[2], state[3], count);
            } else {
                LOG.infof("WP5_AS_PEER_REENTRY v=1 correlation_id=%s endpoint=%s method=%s path=%s count=%d",
                        state[0], state[1], state[2], state[3], count);
            }
        } catch (RuntimeException ignored) {
            // A diagnostic logging failure must not affect Keycloak request handling.
        }
    }

'''


class ReentryPatchError(ValueError):
    """A safe rejection code for an unexpected observer source variant."""

    _CODES = frozenset({"invalid_input", "source_digest_mismatch", "anchor_mismatch"})

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "anchor_mismatch"
        self.code = code
        super().__init__(code)


def _replace_once(source: bytes, anchor: bytes, replacement: bytes) -> bytes:
    if source.count(anchor) != 1:
        raise ReentryPatchError("anchor_mismatch")
    return source.replace(anchor, replacement, 1)


def patch_helper_bytes(source: bytes) -> bytes:
    """Return a v4 probe variant without modifying the v3 helper file."""
    if not isinstance(source, bytes):
        raise ReentryPatchError("invalid_input")
    if hashlib.sha256(source).hexdigest() != V3_HELPER_SHA256:
        raise ReentryPatchError("source_digest_mismatch")

    patched = _replace_once(source, _CONSTANT_ANCHOR, _CONSTANT_REPLACEMENT)
    patched = _replace_once(patched, _OFF_GUARD_ANCHOR, _OFF_GUARD_REPLACEMENT)
    patched = _replace_once(patched, _DUPLICATE_ANCHOR, _DUPLICATE_REPLACEMENT)
    patched = _replace_once(patched, _CORRELATION_ANCHOR, _CORRELATION_REPLACEMENT)
    patched = _replace_once(patched, _METHOD_ANCHOR, _METHOD_INSERT + _METHOD_ANCHOR)
    return patched
