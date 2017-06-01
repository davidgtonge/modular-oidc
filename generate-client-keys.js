const jose = require("node-jose");
const fs = require("fs");
const keystore = jose.JWK.createKeyStore();
keystore.generate("EC", "P-256").then(() => {
  console.log(JSON.stringify(keystore.toJSON(true)));
});
