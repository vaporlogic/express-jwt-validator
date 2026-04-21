'use strict';

/**
 * express-jwt-validator v2.0.0
 *
 * Major rewrite. Changes from v1.x:
 *   - Full HMAC family: HS256, HS384, HS512
 *   - decodeOnly() helper
 *   - audience and issuer claim verification
 *   - nbf (not-before) check
 *   - Configurable header field name
 */

var crypto = require('crypto');

function _base64url(str) {
  return str.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    str.length + (4 - (str.length % 4)) % 4, '='
  );
}

function _decodeToken(token) {
  var parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT: expected 3 segments');
  var header  = JSON.parse(Buffer.from(_base64url(parts[0]), 'base64').toString('utf8'));
  var payload = JSON.parse(Buffer.from(_base64url(parts[1]), 'base64').toString('utf8'));
  return { header, payload, signature: parts[2], raw: token };
}

var ALGO_MAP = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };

function _verifyHmac(token, secret, algorithm) {
  var hash = ALGO_MAP[algorithm];
  if (!hash) throw new Error('Unsupported algorithm: ' + algorithm);
  var parts    = token.split('.');
  var expected = crypto
    .createHmac(hash, secret)
    .update(parts[0] + '.' + parts[1])
    .digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts[2]));
}

function _checkClaims(payload, options) {
  var now = Math.floor(Date.now() / 1000);
  if (options.audience && payload.aud !== options.audience) throw new Error('JWT audience mismatch');
  if (options.issuer   && payload.iss !== options.issuer)   throw new Error('JWT issuer mismatch');
  if (payload.exp && payload.exp < now)  throw new Error('JWT has expired');
  if (payload.nbf && payload.nbf > now)  throw new Error('JWT not yet valid');
}

/**
 * JWT validation middleware.
 *
 * @param {object} options
 * @param {string|Buffer} options.secret
 * @param {string}  [options.algorithm='HS256']
 * @param {string}  [options.tokenField='authorization']
 * @param {string}  [options.audience]
 * @param {string}  [options.issuer]
 * @param {boolean} [options.credentialsRequired=true]
 * @returns {function}
 */
function jwtValidator(options) {
  options = options || {};
  var algorithm  = options.algorithm  || 'HS256';
  var headerName = (options.tokenField || 'authorization').toLowerCase();
  var required   = options.credentialsRequired !== false;

  return function jwtValidatorMiddleware(req, res, next) {
    var headerValue = (req.headers[headerName] || '').trim();
    var token = headerValue.startsWith('Bearer ') ? headerValue.slice(7).trim() : headerValue;

    if (!token) {
      if (required) return res.status(401).json({ error: 'Authorization token required' });
      return next();
    }

    try {
      var decoded = _decodeToken(token);
      if (decoded.header.alg !== algorithm) return res.status(401).json({ error: 'Algorithm mismatch' });
      if (!_verifyHmac(token, options.secret, algorithm)) return res.status(401).json({ error: 'Invalid signature' });
      _checkClaims(decoded.payload, options);
      req.auth = decoded.payload;
      return next();
    } catch (err) {
      return res.status(401).json({ error: err.message });
    }
  };
}

/**
 * Decode without verifying.
 * @param {string} authHeader
 * @returns {{ header, payload } | null}
 */
function decodeOnly(authHeader) {
  var token = (authHeader || '').replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  try { var d = _decodeToken(token); return { header: d.header, payload: d.payload }; }
  catch (_) { return null; }
}

module.exports = jwtValidator;
module.exports.decodeOnly = decodeOnly;
