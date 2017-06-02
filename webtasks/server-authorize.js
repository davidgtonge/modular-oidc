var jwt = require("jsonwebtoken");
var assert = require("assert");
var jwkToPem = require("jwk-to-pem");

module.exports = (context, req, res) => {
  try {
    var IDP_AUTHORIZE = context.secrets.IDP_AUTHORIZE;
    var HOST = context.secrets.HOST;
    var HOST_CB = context.secrets.HOST_CB;
    var key_store = JSON.parse(context.secrets.key_store);
    var pubKey = jwkToPem(key_store.keys[0]);
    var privKey = jwkToPem(key_store.keys[0], { private: true });
    var client = jwt.verify(context.query.client_id, pubKey, {
      algorithm: "ES256"
    });
    assert.equal(client.redirect_uris[0], context.query.redirect_uri);
    var stateToken = jwt.sign(context.query, privKey, {
      algorithm: "ES256",
      expiresIn: 30
    });
    var url = `${IDP_AUTHORIZE}?state=${stateToken}&redirect=${HOST_CB}&issuer=${HOST}`;

    res.writeHead(200, { "Content-Type": "text/html " });
    res.end(
      `
      <!doctype html>
      <html>
        <head>
          <title>Modular OIDC Demo - Authorize</title>
          <meta http-equiv="refresh" content="5;URL='${url}'" />
        </head>
        <body>
          <p>To authorize <strong>${client.client_name}</strong>, please login
          to Google, redirecting...</p>
        </body>
      </html>`
    );
  } catch (e) {
    console.log(e);
    res.writeHead(500);
    res.end();
  }
};
