var jwt = require("jsonwebtoken");
var Issuer = require("openid-client").Issuer;
var jwkToPem = require("jwk-to-pem");
var R = require("ramda");

module.exports = (context, req, res) => {
  var key_store = JSON.parse(context.secrets.key_store);
  var pubKey = jwkToPem(key_store.keys[0]);
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
    .then(() => {
      var stateParams = jwt.verify(context.query.state, pubKey, {
        algorithm: "ES256"
      });

      return client
        .authorizationCallback(context.secrets.redirect_uri, context.query, {
          state: context.query.state
        })
        .then(token => token.claims)
        .then(
          claims =>
            jwt.sign(
              { state: stateParams.state, email: claims.email },
              privKey,
              { algorithm: "ES256" }
            )
        )
        .then(clientToken => {
          var url = `${stateParams.redirect}?token=${clientToken}`;
          res.writeHead(200, { "Content-Type": "text/html " });
          res.end(
            `
            <!doctype html>
            <html>
              <head>
                <title>Modular OIDC Demo - Google RP Callback</title>
                <meta http-equiv="refresh" content="5;URL='${url}'" />
              </head>
              <body>
                <p>Thank you for authenticating yourself via Google, please wait
                while we redirect you...</p>
              </body>
            </html>`
          );
        });
    })
    .catch(err => {
      console.log(err);
      res.writeHead(500);
      res.end();
    });
};
