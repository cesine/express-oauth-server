
/**
 * Module dependencies.
 */
var debug = require('debug')('oauth');
var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var Promise = require('bluebird');
var Request = require('oauth2-server').Request;
var Response = require('oauth2-server').Response;
var UnauthorizedRequestError = require('oauth2-server/lib/errors/unauthorized-request-error');

/**
 * Constructor.
 */

function ExpressOAuthServer(options) {
  options = options || {};
  debug(options);

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.server = new NodeOAuthServer(options);
  debug(this.server);
}

/**
 * Authentication Middleware.
 *
 * Returns a middleware that will validate a token.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-7)
 */

ExpressOAuthServer.prototype.authenticate = function(options) {
  debug('authenticate', options);
  var server = this.server;
  var handleError = this.options.handleError || handleError;

  return function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return server.authenticate(request, response, options);
      })
      .tap(function(token) {
        res.locals.oauth = { token: token };
      })
      .catch(function(e) {
        return handleError(e, req, res);
      })
      .finally(next);
  };
};

/**
 * Authorization Middleware.
 *
 * Returns a middleware that will authorize a client to request tokens.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
 */

ExpressOAuthServer.prototype.authorize = function(options) {
  debug('authorize', options);
  var server = this.server;
  var handleErrorMiddleware = options.handleError || handleError;

  return function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return server.authorize(request, response, options);
      })
      .tap(function(code) {
        res.locals.oauth = { code: code };
      })
      .then(function() {
        return handleResponse(req, res, response);
      })
      .catch(function(e) {
        return handleErrorMiddleware(e, req, res, response);
      })
      .finally(next);
  };
};

/**
 * Grant Middleware.
 *
 * Returns middleware that will grant tokens to valid requests.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
 */

ExpressOAuthServer.prototype.token = function(options) {
  debug('token', options);
  var server = this.server;
  console.log(options);
  var handleErrorMiddleware = options.handleError || handleError;

  return function(req, res, next) {
    debug('token', req.user, res.headers);

    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return server.token(request, response, options);
      })
      .tap(function(token) {
        res.locals.oauth = { token: token };
      })
      .then(function() {
        return handleResponse(req, res, response);
      })
      .catch(function(e) {
        debug(e.stack)
        return handleErrorMiddleware(e, req, res, response);
      })
      .finally(next);
  };
};

/**
 * Handle response.
 */

var handleResponse = function(req, res, response) {
  debug('handleResponse', response.headers);
  res.set(response.headers);
  res.status(response.status).send(response.body);
};

/**
 * Handle error.
 */

var handleError = function(e, req, res, response) {
  debug('handleError', e.stack);

  if (response) {
    res.set(response.headers);
  }

  if (e instanceof UnauthorizedRequestError) {
    return res.status(e.code);
  }

  res.status(e.code).send({ error: e.name, error_description: e.message });
};

/**
 * Export constructor.
 */

module.exports = ExpressOAuthServer;
