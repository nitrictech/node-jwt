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