var jwt = require("jsonwebtoken");
var Issuer = require("openid-client").Issuer;
var jwkToPem = require("jwk-to-pem");
var R = require("ramda");

module.exports = (context, req, res) => {
  var key_store = JSON.parse(context.secrets.key_store);
  var privKey = jwkToPem(key_store.keys[0], { private: true });
  var client;

  Issuer
    .discover(context.secrets.issuer)
    .then(
      issuer =>
        new issuer.Client(
          R.pick([ "client_id", "client_secret" ], context.secrets)
        )
    )
    .then(_client => client = _client)
    .then(
      () =>
        client.authorizationUrl({
          redirect_uri: context.secrets.redirect_uri,
          response_type: "code",
          scope: "openid email",
          state: jwt.sign(context.query, privKey, { algorithm: "ES256" })
        })
    )
    .then(url => {
      res.writeHead(302, { location: url });
      res.end();
    })
    .catch(err => {
      console.log(err);
      res.writeHead(500);
      res.end();
    });
};
