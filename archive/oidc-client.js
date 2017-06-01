const crypto = require("crypto");
const express = require("express");
const { Issuer } = require("openid-client");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const jose = require("node-jose");

const creds = { client_id: "", client_secret: "" };

const secret = crypto.randomBytes(32).toString("hex");
const keystore = jose.JWK.createKeyStore();
const redirect_uri = "http://localhost:3000/cb";

let client, pubKey, privKey;

const app = express();

app.get("/jwks.json", (req, res) => {
  res.send(keystore.toJSON());
});

app.get("/authorize", (req, res) => {
  res.redirect(
    client.authorizationUrl({
      redirect_uri,
      response_type: "code",
      scope: "openid email",
      state: jwt.sign(req.query, secret)
    })
  );
});

app.get("/cb", (req, res) => {
  try {
    const { redirect, state, issuer } = jwt.verify(req.query.state, secret);
    client
      .authorizationCallback(redirect_uri, req.query, {
        state: req.query.state
      })
      .then(token => token.claims)
      .then(
        claims =>
          jwt.sign({ state, email: claims.email }, privKey, {
            algorithm: "ES256"
          })
      )
      .then(clientToken => res.redirect(`${redirect}?token=${clientToken}`));
  } catch (e) {
    console.log(e);
    res.status(500).end();
  }
});

keystore
  .generate("EC", "P-256")
  .then(() => {
    const { keys: [ key ] } = keystore.toJSON(true);
    pubKey = jwkToPem(key);
    privKey = jwkToPem(key, { private: true });
    return Issuer.discover("https://accounts.google.com/");
  })
  .then(issuer => new issuer.Client(creds))
  .then(_client => client = _client)
  .then(() => app.listen(3000, () => console.log("app listening on 3000")));
