(function (root, createEvidenceProjector) {
  const api = createEvidenceProjector();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.FapiDemoEvidence = api;
  }
})(globalThis, function () {
  const CLIENTS = Object.freeze({
    'third-party-fapi-mtls': Object.freeze({
      azp: 'third-party-fapi-mtls',
      routeKey: 'route-a',
      route: 'Route A',
      clientAuth: 'tls_client_auth',
    }),
    'third-party-fapi-pkj-mtls': Object.freeze({
      azp: 'third-party-fapi-pkj-mtls',
      routeKey: 'route-b',
      route: 'Route B',
      clientAuth: 'private_key_jwt',
    }),
  });

  function safeText(value) {
    if (typeof value !== 'string' || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) {
      return 'なし';
    }
    return value || 'なし';
  }

  function thumbprintPrefix(value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
      ? value.slice(0, 12)
      : 'なし';
  }

  function project(evidence, expectedRoute) {
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
      throw new TypeError('API response is not evidence');
    }
    const client = CLIENTS[evidence.azp];
    if (!client || client.routeKey !== expectedRoute) {
      throw new TypeError('API response does not match the selected route');
    }

    return Object.freeze({
      azp: client.azp,
      route: client.route,
      clientAuth: client.clientAuth,
      department: safeText(evidence.department),
      logicalRoute: safeText(evidence.logical_route),
      departmentHeader: safeText(evidence.department_header),
      logicalRouteHeader: safeText(evidence.logical_route_header),
      headerMatches: evidence.header_claims_match === true,
      signatureVerified: evidence.token_signature_verified === true,
      bindingVerified: evidence.binding_verified === true,
      tokenThumbprintPrefix: thumbprintPrefix(evidence.token_certificate_thumbprint),
      clientThumbprintPrefix: thumbprintPrefix(evidence.forwarded_client_certificate_thumbprint),
    });
  }

  return Object.freeze({ project });
});
