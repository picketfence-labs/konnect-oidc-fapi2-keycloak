const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { project } = require('../ui/evidence.js');

const thumbprint = 'A'.repeat(43);
const output = project({
  azp: 'third-party-fapi-pkj-mtls',
  route: 'route-a',
  client_authentication: 'tls_client_auth',
  department: 'engineering',
  logical_route: 'engineering-route',
  department_header: 'engineering',
  logical_route_header: 'engineering-route',
  header_claims_match: true,
  token_signature_verified: true,
  binding_verified: true,
  token_certificate_thumbprint: thumbprint,
  forwarded_client_certificate_thumbprint: thumbprint,
  api_gateway_tls_peer_certificate_thumbprint: 'gateway-to-upstream-secret-sentinel',
  access_token: 'access-token-sentinel',
  refresh_token: 'refresh-token-sentinel',
  cookie: 'cookie-sentinel',
  id_token: 'id-token-sentinel',
}, 'route-b');

assert.equal(output.route, 'Route B');
assert.equal(output.clientAuth, 'private_key_jwt');
assert.equal(output.azp, 'third-party-fapi-pkj-mtls');
assert.equal(output.tokenThumbprintPrefix, thumbprint.slice(0, 12));
assert.equal(output.clientThumbprintPrefix, thumbprint.slice(0, 12));
assert.equal(output.bindingVerified, true);
assert.equal(output.signatureVerified, true);
assert.deepEqual(Object.keys(output).sort(), [
  'azp', 'bindingVerified', 'clientAuth', 'clientThumbprintPrefix', 'department',
  'departmentHeader', 'headerMatches', 'logicalRoute', 'logicalRouteHeader',
  'route', 'signatureVerified', 'tokenThumbprintPrefix',
].sort());
assert.equal(JSON.stringify(output).includes('sentinel'), false);
assert.equal(JSON.stringify(output).includes('api_gateway_tls_peer_certificate_thumbprint'), false);
assert.throws(() => project({ azp: 'unknown-client' }, 'route-a'), /selected route/);
assert.throws(() => project({ azp: 'third-party-fapi-mtls' }, 'route-b'), /selected route/);
assert.equal(project({ azp: 'third-party-fapi-mtls', token_signature_verified: 1 }, 'route-a').signatureVerified, false);

const html = fs.readFileSync(path.join(__dirname, '../ui/index.html'), 'utf8');
assert.match(html, /FapiDemoEvidence\.project\(evidence, selectedRoute\)/);
assert.match(html, /\.textContent = value/);
assert.doesNotMatch(html, /JSON\.stringify\(evidence/);
assert.doesNotMatch(html, /evidence\.client_authentication/);
assert.doesNotMatch(html, /id="raw"|localStorage|sessionStorage|\.innerHTML/);
assert.match(html, /history\.replaceState\(null, '', `\$\{location\.pathname\}\$\{location\.search\}`\)/);

console.log('WP6 UI evidence projection: pass');
