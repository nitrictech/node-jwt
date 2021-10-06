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
import { GetSecretOptions, jwtSecret } from ".";

const domain = "test.example.com"

const secretProvider = jwtSecret({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `https://${domain}/.well-known/jwks.json`
});

let getPubKeySpy;
let getSignKeySpy;


jest.mock('jwks-rsa', () => {
  getPubKeySpy = jest.fn(() => "it's a secret");
  getSignKeySpy = jest.fn(() => ({ getPublicKey: getPubKeySpy }));

  return jest.fn(() => ({
      getSigningKey: getSignKeySpy,
  }));
});

describe('Given an unsupported signing algorithm in the JWT header', () => {
  const header = {
    alg: "NOT_SUPPORTED",
  };

  it('Should return null', async () => {
    const secret = await secretProvider({header} as GetSecretOptions);
    expect(secret).toBeNull();
  });
});

describe('Given a supported signing algorithm in the JWT header', () => {
  const header = {
    alg: "RS256",
    kid: "the-key-id",
  };

  let secret;
  beforeAll(async () => {
    jest.clearAllMocks();
    secret = await secretProvider({header} as GetSecretOptions);
  });

  it('Should call get signing key using the key id', () => {
    expect(getSignKeySpy).toBeCalledWith("the-key-id");
  });

  it('Should call get public key', () => {
    expect(getPubKeySpy).toBeCalledTimes(1);
  });

  it('Should return the secret', () => {
    expect(secret).toBe("it's a secret");
  });
});