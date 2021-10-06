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
import { jwtScopes } from ".";

describe('Given a user with a scopes string with all the required scopes', () => {
  let ctx;

  beforeEach(() => {
    ctx = {
      res: {},
      user: {
        scope: "read:user write:user",
      },
    }
  });

  describe('When all scopes are required', () => {
    const middleware = jwtScopes(["read:user", "write:user"]);
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });
  });

  describe('When some scopes are required', () => {
    const middleware = jwtScopes(["read:user", "write:user"], {
      requireAll: false,
    });
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });
  });
});

describe('Given a user with a scopes string with some of the required scopes', () => {
  let ctx;

  beforeEach(() => {
    ctx = {
      res: {},
      user: {
        scope: "read:user",
      },
    }
  });

  describe('When all scopes are required', () => {
    const middleware = jwtScopes(["read:user", "write:user"]);
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should not call next', () => {
      expect(nextSpy).not.toBeCalled();
    });

    it('Should return 403 status', () => {
      expect(results).toMatchObject({
        res: {
          status: 403,
        },
      });
    });
  });

  describe('When some scopes are required', () => {
    const middleware = jwtScopes(["read:user", "write:user"], {
      requireAll: false,
    });
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });
  });
});

describe('Given a user with a scopes array', () => {
  let ctx;

  beforeEach(() => {
    ctx = {
      res: {},
      user: { scope: ["read:user", "write:user"]},
    }
  });

  describe('When calling the middleware', () => {
    const middleware = jwtScopes(["read:user", "write:user"]);
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });
  });
});

describe('Given a ctx with required scopes with a custom separator', () => {
  let ctx;

  beforeEach(() => {
    ctx = {
      res: {},
      user: { scope: "read:user|write:user"},
    }
  });

  describe('When the separate is specified', () => {
    const middleware = jwtScopes(
      ["read:user", "write:user"],
      {scopeSeparator: "|"}
    );
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });
  });
});

describe('Given a ctx with scopes in a custom location', () => {
  let ctx;

  beforeEach(() => {
    ctx = {
      res: {},
      auth: { permissions: ["read:user", "write:user"]},
    }
  });

  describe('When the property path is specified', () => {
    const middleware = jwtScopes(["read:user", "write:user"], {scopesProperty: "auth.permissions"});
    const nextSpy = jest.fn();
    nextSpy.mockImplementation(ctx => ctx);
    let results;
    let originalCtx;

    beforeEach(async () => {
      originalCtx = JSON.parse(JSON.stringify(ctx));
      nextSpy.mockClear();
      results = await middleware(ctx, nextSpy);
    });

    it('Should not modify the ctx', () => {
      expect(results).toEqual(originalCtx);
    });

    it('Should call next', () => {
      expect(nextSpy).toBeCalledTimes(1);
    });
  });
});