const jose = require("node-jose");

module.exports = (context, cb) => {
  jose.JWK
    .asKeyStore(context.secrets.key_store)
    .then(keyStore => keyStore.toJSON())
    .then(jwks => cb(null, jwks))
    .catch(cb);
};
