'use strict';

/**
 * express-jwt-validator v1.0.0
 *
 * Express middleware for JWT validation.
 * Supports HS256 only. Attaches decoded payload to req.auth.
 */

var crypto = require('crypto');

function _base64url(str) {
  return str.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    str.length + (4 - (str.length % 4)) % 4, '='
  );
}

function _decodeToken(token) {
  var parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT');
  var header  = JSON.parse(Buffer.from(_base64url(parts[0]), 'base64').toString());
  var payload = JSON.parse(Buffer.from(_base64url(parts[1]), 'base64').toString());
  return { header, payload, raw: token };
}

function _verifyHs256(token, secret) {
  var parts    = token.split('.');
  var expected = crypto
    .createHmac('sha256', secret)
    .update(parts[0] + '.' + parts[1])
    .digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts[2]));
}

/**
 * JWT validation middleware (HS256 only).
 *
 * @param {object} options
 * @param {string|Buffer} options.secret
 * @param {boolean} [options.credentialsRequired=true]
 * @returns {function}
 */
function jwtValidator(options) {
  options = options || {};
  var required = options.credentialsRequired !== false;

  return function (req, res, next) {
    var header = (req.headers['authorization'] || '').trim();
    var token  = header.startsWith('Bearer ') ? header.slice(7).trim() : header;

    if (!token) {
      if (required) return res.status(401).json({ error: 'Token required' });
      return next();
    }

    try {
      var decoded = _decodeToken(token);
      if (decoded.header.alg !== 'HS256') {
        return res.status(401).json({ error: 'Only HS256 supported' });
      }
      if (!_verifyHs256(token, options.secret)) {
        return res.status(401).json({ error: 'Invalid signature' });
      }
      var now = Math.floor(Date.now() / 1000);
      if (decoded.payload.exp && decoded.payload.exp < now) {
        return res.status(401).json({ error: 'Token expired' });
      }
      req.auth = decoded.payload;
      return next();
    } catch (err) {
      return res.status(401).json({ error: err.message });
    }
  };
}

module.exports = jwtValidator;
