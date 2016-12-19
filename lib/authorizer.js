var _ = require('lodash')
var request = require('request')
var Session = require('./session')

function AuthorizerOAuth2 (opts) {
  _.extend(this, {
    session: new Session(opts),
    // not used in auth plugin.
    profileUrl: process.env.OAUTH2_PROFILE
  }, opts)
}

AuthorizerOAuth2.prototype.authorize = AuthorizerOAuth2.prototype.whoami = function (credentials, cb) {
  var _this = this
  if (!validateCredentials(credentials)) return cb(error404())
  var token = credentials.headers.authorization.replace('Bearer ', '')
  this.session.get(token, function (err, user) {
    if (err) return cb(err)
    else if (!user.accessToken) return _this.session.oauthURL(cb, token)
    else {
      // since this plugin manages its own caching, let the upstream service
      // know that it should not cache results itself
      user.cacheAllowed = false
      // we hold a lock in redis for a few minutes, to prevent
      // a thundering herd of auth requests.
      _this.session.checkLock(token, function (locked) {
        if (locked) {
          return cb(null, user)
        } else {
          _this._checkToken(user.accessToken, function (err) {
            if (err) {
              return _this.session.oauthURL(cb, token)
            } else {
              _this.session.lock(token)
              return cb(null, user)
            }
          })
        }
      })
    }
  })
}

AuthorizerOAuth2.prototype._checkToken = function (accessToken, cb) {
  request.get({
    url: this.profileUrl,
    headers: {
      'user-agent': 'npm Enterprise'
    },
    auth: {
      bearer: accessToken
    },
    json: true
  }, function (err, res, body) {
    if (res && res.statusCode >= 400) err = Error('token no longer valid status = ' + res.statusCode)
    if (err) return cb(err)
    else return cb(null)
  })
}

function validateCredentials (credentials) {
  if (!credentials) return false
  if (!credentials.headers) return false
  if (!credentials.headers.authorization || !credentials.headers.authorization.match(/Bearer /)) return false
  return true
}

function error404 () {
  var error = Error('not found')
  error.statusCode = 404
  return error
}

AuthorizerOAuth2.prototype.end = function () {
  this.session.end()
}

module.exports = AuthorizerOAuth2
