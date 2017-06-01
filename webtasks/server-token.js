var jwt = require("jsonwebtoken");
var assert = require("assert");
var jwkToPem = require("jwk-to-pem");
var tokenHash = require("oidc-token-hash");

module.exports = (context, cb) => {
  var HOST = context.secrets.HOST;
  var key_store = JSON.parse(context.secrets.key_store);
  var pubKey = jwkToPem(key_store.keys[0]);
  var privKey = jwkToPem(key_store.keys[0], { private: true });

  var codePayload = jwt.verify(context.body.code, pubKey, {
    algorithm: "ES256"
  });

  var privateKeyJwt = context.body.client_assertion;
  var client = jwt.verify(codePayload.client_id, pubKey, {
    algorithm: "ES256"
  });
  var clientPubKey = jwkToPem(client.jwks.keys[0]);
  var clientAuth = jwt.verify(privateKeyJwt, clientPubKey, {
    algorithm: "ES256"
  });
  assert.equal(codePayload.client_id, clientAuth.iss);
  var access_token = jwt.sign(
    {
      sub: codePayload.email,
      scope: codePayload.scope,
      aud: codePayload.client_id
    },
    privKey,
    { algorithm: "ES256", expiresIn: 300 }
  );
  var id_token = jwt.sign(
    {
      iss: HOST,
      sub: codePayload.email,
      aud: codePayload.client_id,
      at_hash: tokenHash.generate(access_token),
      nonce: codePayload.nonce
    },
    privKey,
    { algorithm: "ES256", expiresIn: 300 }
  );
  cb(null, {
    access_token: access_token,
    id_token: id_token,
    expires_in: 300,
    token_type: "Bearer"
  });
};
