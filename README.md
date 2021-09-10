# @nitric/middleware-jwt

This module provides Nitric Node-SDK HTTP Middleware for validating JWTs ([JSON Web Tokens](https://jwt.io)) through the [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken/) module, as well as middleware for validating the users permissions (scope) for RBAC. The decoded JWT payload is made available on the ctx object.

This set of middleware is particularly useful when integrating with external authentication providers such as [Auth0](https://auth0.com)

## Install

```bash
$ npm install @nitric/middleware-jwt
```

## Usage

Basic jwt validation and scope verification using an HS256 secret:

```typescript
import { faas, createHandler } from '@nitric/sdk';
import { jwt, jwtScopes } from '@nitric/middleware-jwt';

faas
  .http(
    // compose a new handler that calls the middleware before your custom code
    createHandler(
      jwt({ secret: 'the-shared-secret', algorithms: ['HS256'] }),
      jwtScopes([ 'create:orders' ]),
      (ctx) => {
        // access the decoded jwt in your code
        console.log(ctx.user.firstName);
      }
    )
  )
  .start();
```

The decoded JWT payload is available on the context object `ctx`, by default it's below a new property `ctx.user`. The output property on the context object can be changed using the `outputProperty` option.

> The default behavior of the module is to extract the JWT from the `Authorization` header as an [OAuth2 Bearer token](https://oauth.net/2/bearer-tokens/).

### Required Parameters
The `algorithms` parameter is required to prevent potential downgrade attacks when providing third party libraries as **secrets**.

:warning: **Do not mix symmetric and asymmetric (ie HS256/RS256) algorithms**: Mixing algorithms without further validation can potentially result in downgrade vulnerabilities.

```javascript
jwt({
  secret: 'the-shared-secret',
  algorithms: ['HS256'],
  //algorithms: ['RS256']
})
```

### Additional Options

You can specify audience and/or issuer as well, which is highly recommended for security purposes:

```typescript
jwt({
  secret: 'the-shared-secret',
  algorithms: ['HS256'],
  verifyOptions: {
    audience: 'http://myapi/protected',
    issuer: 'http://issuer',
  }
})
```

> If the JWT has an expiration (`exp`), it will be checked automatically.

If you are using a base64 URL-encoded secret, pass a `Buffer` with `base64` encoding as the secret instead of a string:

```typescript
jwt({
  secret: Buffer.from('the-shared-secret', 'base64'),
  algorithms: ['RS256'],
})
```

This module also support tokens signed with public/private key pairs. Instead of a secret, you can specify a Buffer with the public key

```typescript
const publicKey = fs.readFileSync('/path/to/public.pub');
jwt({ secret: publicKey, algorithms: ['RS256'] });
```

### Retrieving the Decoded Payload

By default, the decoded token is attached to `ctx.user` but can be configured with the `outputProperty` option.

```javascript
// attach to ctx.auth using outputProperty
jwt({ secret: publicKey, algorithms: ['RS256'], outputProperty: 'auth' });
```

> `outputProperty` uses [lodash.set](https://lodash.com/docs/4.17.2#set) and will accept nested property paths.

### Customizing Token Location

A custom function for extracting the token from a the context can be specified with
the `getToken` option. This is useful if you need to pass the token through a
query parameter or a cookie. You can throw an error in this function and it will
be handled by the middleware, resulting in a 401 Unauthorize response.

```typescript
import { faas, createHandler } from '@nitric/sdk';
import { jwt } from '@nitric/middleware-jwt';

faas
  .http(
    createHandler(
      jwt({
        secret: 'the-shared-secret',
        algorithms: ['HS256'],
        getToken: ({req}) => {
          if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
              return req.headers.authorization.split(' ')[1];
          } else if (req.query && req.query.token) {
            return req.query.token;
          }
          return null;
        }
      }),
      yourHandler,
    )
  )
  .start();
```

### Multi-tenancy

If you are developing an application in which the secret used to sign tokens is not static, you can provide a function as the `secret` parameter. The function has the signature: `function(ctx, header, payload)` and can be sync or async (return a Promise):
* `ctx` (`HttpContext`) - The Nitric SDK HttpContext object, containing keys for request `ctx.req` and response `ctx.res`.
* `header` (`Object`) - An object with the JWT header.
* `payload` (`Object`) - An object with the JWT claims.
For example, if the secret varies based on the [JWT issuer](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#issDef):

```typescript
import { faas, createHandler } from '@nitric/sdk';
import { jwt, jwtScopes } from '@nitric/middleware-jwt';
import data from './data';
import utils from './utils';

const getSecret = async (ctx, header, payload) => {
  const issuer = payload.iss;
  const tenant = await data.getTenantByIdentifier(issuer);
  if (!tenant) {
    throw new Error('missing_secret');
  }

  return utils.decrypt(tenant.secret);
};

faas
  .http(
    createHandler(
      jwt({ secret: getSecret, algorithms: ['HS256'] }),
      yourHandler,
    )
  )
  .start();
```

### Revoked tokens
It is possible that some tokens will need to be revoked so they cannot be used any longer. You can provide a function as the `isRevoked` option. The signature of the function is `function(ctx, payload)`, it should return a boolean and can be sync or async:
* `ctx` (`HttpContext`) - The Nitric SDK HttpContext object, containing keys for request `ctx.req` and response `ctx.res`.
* `payload` (`Object`) - An object with the JWT claims.

For example, if the `(iss, jti)` claim pair is used to identify a JWT:
```typescript
import { faas, createHandler } from '@nitric/sdk';
import { jwt, jwtScopes } from '@nitric/middleware-jwt';
import utils from './utils';

const isRevoked = async (ctx, payload) => {
  const issuer = payload.iss;
  const tokenId = payload.jti;

  // your custom method of querying if the token is revoked.
  return await utils.isRevokedToken(issuer, tokenId);
};

faas
  .http(
    createHandler(
      jwt({
        secret: 'the-shared-secret',
        algorithms: ['HS256'],
        isRevoked
      }),
      yourHandler,
    )
  )
  .start();
```

### Error handling

The default behavior is to return a 401 unauthorized response. You can decorate this middleware if custom behavior is needed.

### Additional Notes

> This module was adapted from code authored by the Auth0 team in their ExpressJS Middleware projects [express-jwt](https://github.com/auth0/express-jwt) and [express-jwt-authz](https://github.com/auth0/express-jwt-authz).