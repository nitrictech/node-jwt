// Copyright 2021, Nitric Technologies Pty Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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