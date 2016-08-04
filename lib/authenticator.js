var _ = require('lodash')
var Session = require('./session')
var uuid = require('uuid')

function AuthenticatorOAuth2 (opts) {
  _.extend(this, {
    session: new Session(opts)
  }, opts)
}

AuthenticatorOAuth2.prototype.authenticate = function (credentials, cb) {
  if (!validateCredentials(credentials)) return cb(error500())

  var token = uuid.v4()

  this.session.oauthURL(function (_, url) {
    return cb(null, {
      token: token,
      user: {
        name: credentials.body.name,
        email: credentials.body.email,
        sso: url
      }
    })
  }, token)
}

AuthenticatorOAuth2.prototype.unauthenticate = function (token, cb) {
  this.session.delete(token, cb)
}

function validateCredentials (credentials) {
  if (!credentials) return false
  if (!credentials.body) return false
  if (!credentials.body.name) return false
  return true
}

AuthenticatorOAuth2.prototype.end = function () {
  this.session.end(true)
}

function error500 () {
  var error = Error('unknown error')
  error.statusCode = 500
  return error
}

module.exports = AuthenticatorOAuth2
