const express = require("express");
const bodyParser = require("body-parser");
const jose = require("node-jose");
const jwkToPem = require("jwk-to-pem");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const crypto = require("crypto");
const tokenHash = require("oidc-token-hash");
const got = require("got");

const HOST = "http://localhost:3001";
const IDP_HOST = "http://localhost:3000";
const keystore = jose.JWK.createKeyStore();
let pubKey, privKey;

const getIdpKey = () => got(IDP_HOST + "/jwks.json")
  .then(res => JSON.parse(res.body))
  .then(({ keys: [ key ] }) => jwkToPem(key));

const app = express();

app.use((req, res, next) => {
  console.log(req.path);
  next();
});

app.get("/jwks.json", (req, res) => {
  res.send(keystore.toJSON());
});

app.get("/.well-known/openid-configuration", (req, res) => {
  res.send({
    issuer: HOST,
    authorization_endpoint: `${HOST}/connect/authorize`,
    token_endpoint: `${HOST}/connect/token`,
    token_endpoint_auth_methods_supported: [ "private_key_jwt" ],
    token_endpoint_auth_signing_alg_values_supported: [ "RS256", "ES256" ],
    id_token_signing_alg_values_supported: [ "RS256", "ES256" ],
    userinfo_endpoint: `${HOST}/connect/userinfo`,
    jwks_uri: `${HOST}/jwks.json`,
    registration_endpoint: `${HOST}/connect/register`,
    response_types_supported: [ "code", "code id_token" ]
  });
});

app.post("/connect/register", bodyParser.json(), (req, res) => {
  const clientId = jwt.sign(req.body, privKey, { algorithm: "ES256" });
  res
    .status(201)
    .send({
      client_id: clientId,
      token_endpoint_auth_method: "private_key_jwt",
      id_token_signed_response_alg: "ES256"
    });
});

app.post("/connect/token", bodyParser.urlencoded(), (req, res) => {
  const { client_id, scope, email, nonce } = jwt.verify(req.body.code, pubKey, {
    algorithm: "ES256"
  });
  const privateKeyJwt = req.body.client_assertion;
  const client = jwt.verify(client_id, pubKey, { algorithm: "ES256" });
  const clientPubKey = jwkToPem(client.jwks.keys[0]);
  const clientAuth = jwt.verify(privateKeyJwt, clientPubKey, {
    algorithm: "ES256"
  });
  assert.equal(client_id, clientAuth.iss);
  const access_token = jwt.sign(
    { sub: email, scope, aud: client_id },
    privKey,
    { algorithm: "ES256", expiresIn: 300 }
  );
  const id_token = jwt.sign(
    {
      iss: HOST,
      sub: email,
      aud: client_id,
      at_hash: tokenHash.generate(access_token),
      nonce
    },
    privKey,
    { algorithm: "ES256", expiresIn: 300 }
  );
  res.send({ access_token, id_token, expires_in: 300, token_type: "Bearer" });
});

app.get("/cb", (req, res) => {
  getIdpKey()
    .then(key => jwt.verify(req.query.token, key, { algorithm: "ES256" }))
    .then(({ state, email }) => {
      const {
        client_id,
        nonce,
        scope,
        redirect_uri
      } = jwt.verify(state, pubKey, { algorithm: "ES256" });
      const codePayload = {
        client_id,
        nonce,
        scope,
        rnd: jose.util.randomBytes(16).toString("hex"),
        email
      };
      const code = jwt.sign(codePayload, privKey, {
        algorithm: "ES256",
        expiresIn: 30
      });
      const id_token = jwt.sign(
        {
          iss: HOST,
          aud: client_id,
          sub: client_id,
          c_hash: tokenHash.generate(code),
          nonce
        },
        privKey,
        { algorithm: "ES256", expiresIn: 300 }
      );
      res.redirect(`${redirect_uri}?code=${code}&id_token=${id_token}`);
    });
});

app.get("/connect/authorize", (req, res) => {
  try {
    const { redirect_uri, client_id, scope, nonce } = req.query;
    const client = jwt.verify(client_id, pubKey, { algorithm: "ES256" });
    assert.equal(client.redirect_uris[0], redirect_uri);
    const statePayload = { client_id, redirect_uri, nonce, scope };
    const stateToken = jwt.sign(statePayload, privKey, {
      algorithm: "ES256",
      expiresIn: 30
    });
    res.redirect(
      `${IDP_HOST}/authorize?state=${stateToken}&redirect=${HOST}/cb&issuer=${HOST}`
    );
  } catch (e) {
    console.log(e);
    res.status(500).end();
  }
});

keystore.generate("EC", "P-256").then(() => {
  const { keys: [ key ] } = keystore.toJSON(true);
  pubKey = jwkToPem(key);
  privKey = jwkToPem(key, { private: true });
  app.listen(3001, () => {
    console.log("server listening on 3001");
  });
});
