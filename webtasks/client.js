var Issuer = require("openid-client").Issuer;
var Webtask = require("webtask-tools");
var jose = require("node-jose");
var express = require("express");

var nonce = jose.util.randomBytes(16).toString("hex");
// hack to avoid sessions...
var keystore = jose.JWK.createKeyStore();
var app = express();

var client;

app.get("/", (req, res) => {
  res.send(
    `
    <!doctype html>
    <html>
      <head>
        <title>Modular OIDC Demo - Client</title>

      </head>
      <body>
        <p>Demo of modular OIDC using webtasks.io. For further details see:
        <a href="https://github.com/davidgtonge/modular-oidc">https://github.com/davidgtonge/modular-oidc</a></p>
        <ol>
          <li><a href="/client/register">Register a client</a></li>
          <li><a href="/client/authorize">Authorize</a></li>
        </ol>
      </body>
    </html>`
  );
});

app.get("/authorize", (req, res) => {
  var HOST = req.webtaskContext.secrets.HOST;
  var redirect_uri = `${HOST}/cb`;
  res.redirect(
    client.authorizationUrl({
      redirect_uri: redirect_uri,
      response_type: "code id_token",
      scope: "openid",
      nonce: nonce
    })
  );
});

app.get("/cb", (req, res) => {
  var HOST = req.webtaskContext.secrets.HOST;
  var redirect_uri = `${HOST}/cb`;
  client
    .authorizationCallback(redirect_uri, req.query, { nonce: nonce })
    .then(tokenSet => res.json(tokenSet.claims))
    .catch(err => res.send(err));
});

app.get("/register", (req, res) => {
  var HOST = req.webtaskContext.secrets.HOST;
  var redirect_uri = `${HOST}/cb`;
  var clientData = { redirect_uris: [ redirect_uri ], client_name: "Webtask" };
  keystore
    .generate("EC", "P-256")
    .then(() => Issuer.discover(req.webtaskContext.secrets.ISSUER))
    .then(issuer => issuer.Client.register(clientData, { keystore }))
    .then(_client => client = _client)
    .then(() => {
      res.send(
        `Client succesfully registered with ${req.webtaskContext.secrets.ISSUER}. ID: ${client.client_id}`
      );
    });
});

module.exports = Webtask.fromExpress(app);
