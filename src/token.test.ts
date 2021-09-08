import { AuthenticateOptions, jwt } from ".";

describe('Given no options', () => {
  it('Should throw an error', () => {
    expect(jwt).toThrow("secret must be provided");
  });
});

describe('Given options without algorithms set', () => {
  const optionsWithoutAlgo = {
    secret: "testsecret",
  } as AuthenticateOptions;

  it('Should throw an error', () => {
    expect(() => jwt(optionsWithoutAlgo)).toThrow("algorithms must be set");
  });
});

describe('Given options with invalid algorithms', () => {
  const optionsWithInvalidAlgo: AuthenticateOptions = {
    secret: "testsecret",
    algorithms: ["FAKE"] as any,
  };

  it('Should throw an error', () => {
    expect(() => jwt(optionsWithInvalidAlgo)).toThrow("unsupported algorithm FAKE, supported algorithms are RS256, HS256");
  });
});

describe('Given options with a secret and algorithms', () => {
  const options: AuthenticateOptions = {
    secret: "testsecret",
    algorithms: ["RS256"],
  };

  const result = jwt(options);

  describe('When calling jwt', () => {
    it('Should return a middleware function', () => {
      expect(typeof result).toBe('function');
    });
  });
});

describe('Given a request with no authorization header', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object.
    ctx = {
      req: {},
      res: { status: 201 },
    } as any;
  });

  describe('When credentials are required', () => {
    let result;
    
    beforeEach(async () => {
      result = await jwt({secret: 'shh', algorithms: ['RS256'], credentialsRequired: true})(ctx);
    });

    it('Should return an 403 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });

  describe('When credentials are not required', () => {
    let result;
    
    beforeEach(async () => {
      result = await jwt({secret: 'shh', algorithms: ['RS256'], credentialsRequired: false})(ctx, ctx => ctx);
    });

    it('Shouldn\'t change the response status', async () => {
      expect(result.res.status).toBe(201);
    });
  });
});