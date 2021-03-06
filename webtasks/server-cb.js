var jwt = require("jsonwebtoken");
var assert = require("assert");
var jwkToPem = require("jwk-to-pem");
var got = require("got");
var crypto = require("crypto");
var tokenHash = require("oidc-token-hash");

module.exports = (context, req, res) => {
  var key_store = JSON.parse(context.secrets.key_store);
  var pubKey = jwkToPem(key_store.keys[0]);
  var privKey = jwkToPem(key_store.keys[0], { private: true });

  got(context.secrets.IDP_JWKS_URI)
    .then(res => JSON.parse(res.body))
    .then(jwks => jwkToPem(jwks.keys[0]))
    .then(key => jwt.verify(context.query.token, key, { algorithm: "ES256" }))
    .then(payload => {
      var statePayload = jwt.verify(payload.state, pubKey, {
        algorithm: "ES256"
      });
      var client = jwt.verify(statePayload.client_id, pubKey, {
        algorithm: "ES256"
      });
      var codePayload = {
        client_id: statePayload.client_id,
        nonce: statePayload.nonce,
        scope: statePayload.scope,
        rnd: crypto.randomBytes(16).toString("hex"),
        email: payload.email
      };
      var code = jwt.sign(codePayload, privKey, {
        algorithm: "ES256",
        expiresIn: 30
      });
      var id_token = jwt.sign(
        {
          iss: context.secrets.HOST,
          aud: statePayload.client_id,
          sub: statePayload.client_id,
          c_hash: tokenHash.generate(code),
          nonce: statePayload.nonce
        },
        privKey,
        { algorithm: "ES256", expiresIn: 300 }
      );

      var url = `${statePayload.redirect_uri}?code=${code}&id_token=${id_token}`;
      res.writeHead(200, { "Content-Type": "text/html " });
      res.end(
        `
        <!doctype html>
        <html>
          <head>
            <title>Modular OIDC Demo - Callback</title>
            <meta http-equiv="refresh" content="5;URL='${url}'" />
          </head>
          <body>
            <p>Thank you for authorizing <strong>${client.client_name}</strong>
            with the scope of <strong>${statePayload.scope}</strong>, please
            wait while we redirect you back with an auth code...</p>
          </body>
        </html>`
      );
    });
};
