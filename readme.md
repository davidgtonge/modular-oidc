## Modular OIDC Experiment

This repo is an experiment in a modularised stateless OpenID Connect OP and RP.

The experiment uses webtasks from Auth0 which allow individual functions to run as http endpoints.

The result is an OIDC OP that meets enough of the spec to work with the excellent `openid-client` library from `@panva`.

The project is completely stateless and uses no sessions or database storage whatsoever. This is achieved mainly through the use of asymmetric crypto and JWTs:

### Dynamic Client Registration
There is a webtask for this. Rather than inserting the client metadata into a table, it simply returns a client id that is a signed JWT of the metadata. This enables any other webtasks that need client metadata to extract it from the client_id. This is possible because all the OP webtasks share access to the same key-pair.

### Authorization Params
To demonstrate a full OIDC flow the OP actually calls out to another webtask that is an OIDC RP to Google. In order to keep the *state* of the authorization request we put all the auth params into the state param as a JWT -> we then pass this param off to the Google OIDC Client webtask and receive it back via a callback.

### Authorization Code
The authorization code is also generated as a JWT with a short lifetime. This JWT is opaque to the client, but contains the necessary data for another webtask to exchange it for an access token and a refresh token. Currently this data is unencrypted - but it would be fairly easy to use JWEs rather than JWSs.

## Running the code

1. `npm run create-keys` - this will create keypairs for the RP and OP web tasks.
2. `cp ./secrets/_google.creds ./secrets/google.creds` and fill in the details
3. Adjust `server.creds` and `client.creds` to use urls specific to your webtask cluster.
4. `npm run deploy` (you will need to first install `wt-cli` and run `wt init`)
5. Visit the last url output from the above command (the client)
