const { Issuer } = require("openid-client");
const jose = require("node-jose");
const got = require("got");
const express = require("express");
const { URL } = require("url");

const HOST = "http://localhost:3002";
const ISSUER = "https://wt-a59efb2d5e8c0b994fb39e2d67a207be-0.run.webtask.io/.well-known/openid-configuration";

const redirect_uri = `${HOST}/cb`;
const clientData = { redirect_uris: [ redirect_uri ], client_name: "Webtask" };
const nonce = jose.util.randomBytes(16).toString("hex");
const keystore = jose.JWK.createKeyStore();

const app = express();

let client;

app.get("/authorize", (req, res) => {
  res.redirect(
    client.authorizationUrl({
      redirect_uri: redirect_uri,
      response_type: "code id_token",
      scope: "openid",
      nonce
    })
  );
});

app.get("/cb", (req, res) => {
  console.log(req.query);
  client
    .authorizationCallback(redirect_uri, req.query, { nonce })
    .then(tokenSet => res.json(tokenSet.claims))
    .catch(err => res.send(err));
});

keystore
  .generate("EC", "P-256")
  .then(() => Issuer.discover(ISSUER))
  .then(issuer => issuer.Client.register(clientData, { keystore }))
  .then(_client => client = _client)
  .then(() => app.listen(3002, () => console.log("listening on 3002")));
