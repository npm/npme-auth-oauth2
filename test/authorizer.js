var Authorizer = require('../lib/authorizer')
var Session = require('../lib/session')
var tap = require('tap')
var nock = require('nock')

var userComplete = {name: 'bcoe', email: 'ben@example.com', accessToken: 'abc123'}
var userNotComplete = {name: 'bcoe', email: 'ben@example.com'}

var session = new Session()

process.env.OAUTH2_AUTHORIZATION_PATH = 'https://auth.example.com'
process.env.OAUTH2_PROFILE = 'https://api.github.com/user'

tap.test('it responds with session object if SSO dance is complete', function (t) {
  var authorizer = new Authorizer()
  var profile = nock('https://api.github.com')
    .get('/user')
    .reply(200)

  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')

      profile.done()
      t.equal(err, null)
      t.equal(user.email, 'ben@example.com')
      t.end()
    })
  })
})

tap.test('it returns error with login url if access token is no longer valid', function (t) {
  var authorizer = new Authorizer()
  var profile = nock('https://api.github.com')
    .get('/user')
    .reply(401)

  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')

      profile.done()
      t.ok(err.message.indexOf('visit https://auth.example.com') !== -1)
      t.end()
    })
  })
})

tap.test('it returns error with login url if SSO dance is not complete', function (t) {
  var authorizer = new Authorizer()
  session.set('ben@example.com-abc123', userNotComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')

      t.ok(err.message.indexOf('visit https://auth.example.com') !== -1)
      t.end()
    })
  })
})

tap.test('after', function (t) {
  session.end(true)
  t.end()
})
