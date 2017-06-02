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
      res.writeHead(200, { "Content-Type": "text/html " });
      res.end(
        `
        <!doctype html>
        <html>
          <head>
            <title>Modular OIDC Demo - Google RP Authorize</title>
            <meta http-equiv="refresh" content="5;URL='${url}'" />
          </head>
          <body>
            <p>Please wait while we redirect you to Google...</p>
          </body>
        </html>`
      );
    })
    .catch(err => {
      console.log(err);
      res.writeHead(500);
      res.end();
    });
};
