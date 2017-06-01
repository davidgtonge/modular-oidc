var jwt = require("jsonwebtoken");
var jwkToPem = require("jwk-to-pem");

module.exports = (context, cb) => {
  var key_store = JSON.parse(context.secrets.key_store);
  var privKey = jwkToPem(key_store.keys[0], { private: true });
  var clientId = jwt.sign(context.body, privKey, { algorithm: "ES256" });
  cb(null, {
    client_id: clientId,
    token_endpoint_auth_method: "private_key_jwt",
    id_token_signed_response_alg: "ES256"
  });
};
