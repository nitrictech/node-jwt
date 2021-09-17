import jwksRsa = require("jwks-rsa");
import { GetSecretOptions } from ".";
import supportedAlgos from './config';

export const jwtSecret = (options) => {
  if (options === null || options === undefined) {
    // TODO: do something else here.
    throw new Error('An options object must be provided when initializing expressJwtSecret');
  }

  const client = jwksRsa(options);
  // const onError = options.handleSigningKeyError || handleSigningKeyError;

  const secretProvider = async ({header}: GetSecretOptions) => {
    if (!header || !supportedAlgos.includes(header.alg)) {
      return null;
    }

    try {
      const key = await client.getSigningKey(header.kid);
      return key.getPublicKey();
    } catch (err) {
      throw err;
    }
  };
  return secretProvider;
};