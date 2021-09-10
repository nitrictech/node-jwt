import { AuthenticateOptions, jwt } from ".";
import jsonwebtoken from 'jsonwebtoken';

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
  const nextSpy = jest.fn();

  beforeEach(async () => {
    // reset the context object.
    ctx = {
      req: {},
      res: { status: 201 },
    } as any;
    nextSpy.mockClear();
  });

  describe('When credentials are required', () => {
    let result;
    
    beforeEach(async () => {
      result = await jwt({secret: 'shh', algorithms: ['RS256']})(ctx);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });

  describe('When credentials are not required', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    
    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: 'shh', algorithms: ['RS256'], credentialsRequired: false})(ctx, nextSpy);
    });

    it('Should call next with ctx', () => {
      expect(nextSpy).toBeCalledTimes(1);
      expect(nextSpy).toBeCalledWith(ctx);
    });

    it('Should not change the response status', () => {
      expect(result.res.status).toBe(201);
    });
  });
});

describe('Given CORS preflight request', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object.
    ctx = {
      req: {
        method: 'OPTIONS',
        headers: {
          'access-control-request-headers': ['sasa, sras,  authorization'],
        },
      },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextResponse = "fake response";
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(_ => nextResponse);
    let originalCtx;

    beforeEach(async () => {
      nextSpy.mockClear();
      // roughly clone the ctx object
      originalCtx = JSON.parse(JSON.stringify(ctx));
      result = await jwt({secret: 'shh', algorithms: ['RS256']})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the input ctx', async () => {
      expect(ctx).toEqual(originalCtx);
    });

    it('Should not modify the ctx from next', () => {
      expect(result).toBe(nextResponse);
    });
  });
});

describe('Given a malformed authorization header', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object with malformed header
    ctx = {
      req: { headers: { 'authorization': ['wrong'] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: 'shh', algorithms: ['RS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given an authorization header that is not Bearer', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object with malformed header
    ctx = {
      req: { headers: { 'authorization': ['Basic foobar'] } },
      res: { status: 200 },
    } as any;
  });

  describe('When credentials are required', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: 'shh', algorithms: ['RS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });

  describe('When credentials are not required', () => {
    let result;
    const nextResponse = "fake response";
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(_ => nextResponse);
    let originalCtx;

    beforeEach(async () => {
      nextSpy.mockClear();
      // roughly clone the ctx object
      originalCtx = JSON.parse(JSON.stringify(ctx));
      result = await jwt({secret: 'shh', algorithms: ['RS256'], credentialsRequired: false})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalled();
    });

    it('Should not modify the input ctx', async () => {
      expect(ctx).toEqual(originalCtx);
    });

    it('Should not modify the ctx from next', async () => {
      expect(result).toBe(nextResponse);
    });
  });
});

describe('Given a malformed jwt', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object with malformed header
    ctx = {
      req: { headers: { 'authorization': ['Bearer wrongjwt'] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: 'shh', algorithms: ['RS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given a jwt with invalid JSON', () => {
  let ctx;

  beforeEach(async () => {
    // reset the context object with jwt with invalid JSON
    ctx = {
      req: { headers: { 'authorization': ['Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.junk'] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: 'shh', algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given a jwt with an unexpected audience', () => {
  let ctx;
  const secret = 'itsasecret';
  const expectedAudience = 'expected-audience';
  

  beforeEach(async () => {
    // reset the context object with valid jwt, with unexpected audience
    const token = jsonwebtoken.sign({foo: 'bar', aud: 'not-expected-audience'}, secret, { expiresIn: 500});
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256'], verifyOptions: {audience: expectedAudience}})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given an expired jwt', () => {
  let ctx;
  const secret = 'itsasecret';
  

  beforeEach(async () => {
    // reset the context object with an expired jwt
    const token = jsonwebtoken.sign({foo: 'bar', exp: 1382412921 }, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When credentials are required', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });

  describe('When credentials are not required', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256'], credentialsRequired: false})(ctx, nextSpy);
    });

    it('Should still not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should still return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given an invalid jwt', () => {
  let ctx;
  const secret = 'itsasecret';
  

  beforeEach(async () => {
    // reset the context object with an expired jwt
    const token = jsonwebtoken.sign({foo: 'bar', exp: 1382412921 }, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When credentials are required', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: "anothersecret", algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });

  describe('When credentials are not required', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: "anothersecret", algorithms: ['HS256'], credentialsRequired: false})(ctx, nextSpy);
    });

    it('Should still not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should still return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given a custom getToken function', () => {
  let ctx;
  const secret = 'itsasecret';
  

  beforeEach(async () => {
    // provide a valid ctx
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When getToken throws', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({
        secret,
        algorithms: ['HS256'],
        getToken: () => {
          throw new Error('failed');
        }
      })(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given a jwt with an invalid signature', () => {
  let ctx;
  const secret = 'itsasecret';
  

  beforeEach(async () => {
    const [header, payload, signature] = jsonwebtoken.sign({foo: 'bar'}, secret).split('.');
    const newPayload = Buffer.from(JSON.stringify({foo: 'bar', edg: 'ar'})).toString('base64');
    // token with payload modified after signing.
    const token = [header, newPayload, signature].join(".");
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return a 401 error status response', async () => {
      expect(result.res.status).toBe(401);
    });
  });
});

describe('Given a valid jwt', () => {
  let ctx;
  const secret = 'itsasecret';
  
  beforeEach(async () => {
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => {
      if (!ctx) throw new Error('no ctx received by next function');
      return ctx;
    });

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the response status', () => {
      expect(result.res.status).toBe(200);
    });
    
    it('Should add the user to the ctx', () => {
      // jwt payload decoded and returned in ctx.user
      expect(result.user).toMatchObject({foo: 'bar'});
    });
  });
});

describe('Given a valid jwt', () => {
  let ctx;
  const secret = 'itsasecret';
  
  beforeEach(async () => {
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When storing output in a custom nested property', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => {
      if (!ctx) throw new Error('no ctx received by next function');
      return ctx;
    });

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256'], outputProperty: 'auth.custom'})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the response status', () => {
      expect(result.res.status).toBe(200);
    });
    
    it('Should add the token payload to the ctx under the custom property', () => {
      // jwt payload decoded and returned in ctx.user
      expect(result.auth.custom).toMatchObject({foo: 'bar'});
    });
  });
});

describe('Given a Buffer secret and valid jwt', () => {
  let ctx;
  const secret = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
  
  beforeEach(async () => {
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => {
      if (!ctx) throw new Error('no ctx received by next function');
      return ctx;
    });

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the response status', () => {
      expect(result.res.status).toBe(200);
    });
    
    it('Should add the user to the ctx', () => {
      // jwt payload decoded and returned in ctx.user
      expect(result.user).toMatchObject({foo: 'bar'});
    });
  });
});

describe('Given a custom getToken function that returns a valid token', () => {
  let ctx;
  const secret = 'itsasecret';
  
  beforeEach(async () => {
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'custom': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  const getTokenCustom = ctx => ctx.req.headers['custom'][0].split(" ")[1];

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => {
      if (!ctx) throw new Error('no ctx received by next function');
      return ctx;
    });

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret, algorithms: ['HS256'], getToken: getTokenCustom})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the response status', () => {
      expect(result.res.status).toBe(200);
    });
    
    it('Should add the token payload to ctx.user', () => {
      // jwt payload decoded and returned in ctx.user
      expect(result.user).toMatchObject({foo: 'bar'});
    });
  });
});

describe('Given a valid jwt and a custom get secret function', () => {
  let ctx;
  const secret = 'itsasecret';
  const secretSpy = jest.fn();
  secretSpy.mockImplementation(ctx => {
    if (!ctx) throw new Error('no ctx received by next function');
    return secret;
  });
  
  beforeEach(async () => {
    secretSpy.mockClear();
    const token = jsonwebtoken.sign({foo: 'bar'}, secret);
    ctx = {
      req: { headers: { 'authorization': [`Bearer ${token}`] } },
      res: { status: 200 },
    } as any;
  });

  describe('When calling the middleware', () => {
    let result;
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => {
      if (!ctx) throw new Error('no ctx received by next function');
      return ctx;
    });

    beforeEach(async () => {
      nextSpy.mockClear();
      result = await jwt({secret: secretSpy, algorithms: ['HS256']})(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should call the secret function', () => {
      expect(secretSpy).toBeCalledTimes(1);
    });

    it('Should not modify the response status', () => {
      expect(result.res.status).toBe(200);
    });
    
    it('Should add the user to the ctx', () => {
      // jwt payload decoded and returned in ctx.user
      expect(result.user).toMatchObject({foo: 'bar'});
    });
  });
});