module.exports = (context, cb) => {
  cb(null, {
    issuer: context.secrets.HOST,
    authorization_endpoint: context.secrets.AUTH_ENDPOINT,
    token_endpoint: context.secrets.TOKEN_ENDPOINT,
    token_endpoint_auth_methods_supported: [ "private_key_jwt" ],
    token_endpoint_auth_signing_alg_values_supported: [ "RS256", "ES256" ],
    id_token_signing_alg_values_supported: [ "RS256", "ES256" ],
    jwks_uri: context.secrets.JWKS_URI,
    registration_endpoint: context.secrets.REGISTRATION_ENDPOINT,
    response_types_supported: [ "code", "code id_token" ]
  });
};
