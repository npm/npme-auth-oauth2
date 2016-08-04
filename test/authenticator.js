var client = require('redis').createClient()
client.unref()

var Authenticator = require('../lib/authenticator')
var tap = require('tap')

var credentials = {
  name: 'foo',
  password: 'bar',
  email: 'ben@example.com'
}

process.env.OAUTH2_AUTHORIZATION_PATH = 'https://auth.example.com'

tap.test('it generates a token and returns a session on login', function (t) {
  var authenticator = new Authenticator()

  authenticator.authenticate({
    body: credentials
  }, function (err, s) {
    authenticator.end()

    t.assert(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.test(s.token))
    t.equal(s.user.name, 'foo')
    t.equal(s.user.email, 'ben@example.com')
    t.assert(/https:\/\/auth\.example\.com/.test(s.user.sso))
    t.equal(err, null)
    t.end()
  })
})

tap.test('after', function (t) {
  client.end(true)
  t.end()
})
