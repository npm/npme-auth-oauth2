var _ = require('lodash')
var oauth2 = require('simple-oauth2')
var redis = require('redis')

function SessionOAuth2 (opts) {
  _.extend(this, {
    sessionLookupPrefix: 'user-',
    sessionLockPrefix: 'user-token-lock-',
    lockTime: toInt(process.env.AUTHZ_CACHE_DEFAULT_TTL_SECONDS, 300),
    client: redis.createClient(process.env.LOGIN_CACHE_REDIS),
    clientId: process.env.OAUTH2_CLIENT_ID,
    clientSecret: process.env.OAUTH2_CLIENT_SECRET,
    site: process.env.OAUTH2_SITE,
    tokenPath: process.env.OAUTH2_TOKEN_PATH,
    authorizationPath: process.env.OAUTH2_AUTHORIZATION_PATH,
    redirectUri: process.env.OAUTH2_REDIRECT_URI,
    scope: process.env.OAUTH2_SCOPE,
    // not used in auth plugin.
    profileUrl: process.env.OAUTH2_PROFILE,
    emailKey: process.env.OAUTH2_EMAIL_KEY,
    userKey: process.env.OAUTH2_USER_KEY
  }, opts)

  this.oauth2 = oauth2({
    clientID: this.clientId,
    clientSecret: this.clientSecret,
    site: this.site,
    tokenPath: this.tokenPath,
    authorizationPath: this.authorizationPath
  })
}

SessionOAuth2.prototype.get = function (key, cb) {
  var _this = this

  key = normalizeKey(key)

  this.client.get(_this.sessionLookupPrefix + key, function (err, user) {
    if (err) return cb(error500())
    if (!user) return _this.oauthURL(cb)

    return cb(null, JSON.parse(user))
  })
}

SessionOAuth2.prototype.checkLock = function (key, cb) {
  var _this = this

  key = normalizeKey(key)

  this.client.get(_this.sessionLockPrefix + key, function (_err, lock) {
    if (lock) return cb(true)
    else return cb(false)
  })
}

SessionOAuth2.prototype.set = function (key, user, cb) {
  var _this = this

  key = normalizeKey(key)

  _this.client.set(this.sessionLookupPrefix + key, JSON.stringify(user), cb)
}

SessionOAuth2.prototype.lock = function (key) {
  var _this = this

  key = normalizeKey(key)

  _this.client.setex(this.sessionLockPrefix + key, this.lockTime, 'locked')
}

SessionOAuth2.prototype.unlock = function (key) {
  var _this = this

  key = normalizeKey(key)

  _this.client.del(this.sessionLockPrefix + key)
}

SessionOAuth2.prototype.delete = function (key, cb) {
  key = normalizeKey(key)

  this.client.del(this.sessionLookupPrefix + key, this.sessionTimeoutPrefix + key, cb)
}

function normalizeKey (token) {
  return token.replace(/^user-/, '')
}

SessionOAuth2.prototype.end = function () {
  this.client.end(true)
}

SessionOAuth2.prototype.oauthURL = function (cb, relayState) {
  // Authorization uri definition
  var authUrl = this.oauth2.authCode.authorizeURL({
    redirect_uri: this.redirectUri,
    scope: this.scope,
    state: relayState
  })

  process.nextTick(function () {
    var error = Error('visit ' + authUrl + ' to validate your session')
    error.statusCode = 401
    return cb(error, authUrl)
  })
}

function error500 () {
  var error = Error('unknown error')
  error.statusCode = 500
  return error
}

function toInt (val, _default) {
  const integer = parseInt(val, 10)
  return isNaN(integer) ? _default : integer
}

module.exports = SessionOAuth2
