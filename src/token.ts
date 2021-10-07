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
import jsonwebtoken from 'jsonwebtoken';
import { set } from 'lodash';
import { faas } from '@nitric/sdk';
import { HttpContext, HttpMiddleware } from '@nitric/sdk/lib/faas';

export interface GetSecretOptions {
  ctx: HttpContext;
  header: any;
  payload: any;
}

const errorContext = (
  ctx: HttpContext,
  status = 500,
  details?: string
): HttpContext => {
  ctx.res.status = status;
  ctx.res.body = details;
  return ctx;
};

export type SigningAlgorithm = 'RS256' | 'HS256';
const supportedAlgorithms = ['RS256', 'HS256'];

export interface AuthenticateOptions {
  secret:
    | string
    | Buffer
    | ((args: GetSecretOptions) => Promise<string | Buffer> | string | Buffer);
  algorithms: SigningAlgorithm[];
  isRevoked?: (ctx: HttpContext, payload: any) => Promise<boolean> | boolean;
  /**
   * The property name on the output context that should store the decoded token.
   *
   * By default the token will be stored in ctx.user
   *
   * Note: internally uses lodash.set, so will accept nested property paths.
   *
   * @default "user"
   */
  outputProperty?: string;
  /**
   * Used to determine whether this middleware will permit unauthenticated requests to pass through.
   *
   * Useful when a handler supports both authenticated and unauthenticated request.
   *
   * If true, the middleware will return 403 Unauthorize for any incoming request without an Authorization Header.
   * If false, requests with a token will be validated and decoded, requests without a token will continue without a decoded token value.
   *
   * @default true
   *
   */
  credentialsRequired?: boolean;
  /**
   * A custom function for extracting the token from a request can be specified with the getToken option.
   * This is useful if you need to pass the token through a query parameter or a cookie.
   * You can throw an error in this function and it will be handled by @nitric/node-jwt.
   */
  getToken?: (ctx: HttpContext) => Promise<string> | string;
  verifyOptions?: jsonwebtoken.VerifyOptions;
}

const defaultOptions: Omit<AuthenticateOptions, 'secret' | 'algorithms'> = {
  isRevoked: async () => false,
  outputProperty: 'user',
  credentialsRequired: true,
};

export const jwt = (options: AuthenticateOptions): faas.HttpMiddleware => {
  const {
    secret,
    algorithms,
    isRevoked,
    credentialsRequired,
    getToken,
    outputProperty,
    verifyOptions,
  } = { ...defaultOptions, ...options };

  // Validate input options
  if (!secret) throw new Error('secret must be provided');
  if (!algorithms) throw new Error('algorithms must be set');
  if (!Array.isArray(algorithms))
    throw new Error('algorithms must be an array');
  if (!algorithms.every((algo) => supportedAlgorithms.includes(algo))) {
    const invalidAlgorithms = algorithms.filter(
      (algo) => !supportedAlgorithms.includes(algo)
    );
    throw new Error(
      `unsupported algorithm${
        invalidAlgorithms.length > 1 ? 's' : ''
      } ${invalidAlgorithms.join(
        ', '
      )}, supported algorithms are ${supportedAlgorithms.join(', ')}`
    );
  }

  const middleware: faas.HttpMiddleware = async (ctx, next) => {
    let token;

    if (
      ctx.req.method === 'OPTIONS' &&
      ctx.req.headers.hasOwnProperty('access-control-request-headers')
    ) {
      const hasAuthInAccessControl =
        ctx.req.headers['access-control-request-headers'][0]
          .split(',')
          .map((header) => header.trim())
          .indexOf('authorization') >= 0;
      if (hasAuthInAccessControl) {
        return await next(ctx);
      }
    }

    if (getToken && typeof getToken === 'function') {
      try {
        token = await getToken(ctx);
      } catch (e) {
        //TODO: Set 500 error here. something unexpected went wrong.
        console.log(`call to custom getToken function failed with error: ${e}`);
        return errorContext(ctx, 401);
      }
      // TODO: check what req.headers.authorization does in Express.
    } else if (ctx.req.headers && ctx.req.headers.authorization) {
      const parts = (
        typeof ctx.req.headers.authorization === 'string'
          ? ctx.req.headers.authorization
          : ctx.req.headers.authorization[0]
      ).split(' ');

      if (parts.length == 2) {
        const [scheme, credentials] = parts;

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          if (credentialsRequired) {
            // return next(new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' }));
            // TODO: log
            console.error('credentials_bad_format');
            console.error('no Bearer prefix');
            return errorContext(ctx, 401);
          } else {
            return await next(ctx);
          }
        }
      }
    }

    if (!token) {
      if (credentialsRequired) {
        // TODO: set error before return
        // return next(new UnauthorizedError('credentials_required', { message: 'No authorization token was found' }));
        console.error('credentials_required', 'no token found');
        return errorContext(ctx, 401);
      } else {
        return await next(ctx);
      }
    }

    let dtoken;
    try {
      dtoken = jsonwebtoken.decode(token, { complete: true }) || {};
    } catch (err) {
      // TODO: set unauthenticated error before returning.
      // log invalid token.
      console.log('invalid_token', 'unable to decode token');
      return errorContext(ctx, 401);
    }

    // 1. Get the secret value
    const secretValue: string | Buffer =
      typeof secret !== 'function'
        ? secret
        : await secret({
            ctx,
            header: dtoken.header,
            payload: dtoken.payload,
          });

    // 2. Verify the token
    let verifiedPayload: jsonwebtoken.JwtPayload;
    try {
      verifiedPayload = await new Promise((res, rej) => {
        jsonwebtoken.verify(
          token,
          secretValue,
          verifyOptions,
          (err, decoded) => {
            if (err) {
              console.error('invalid_token', 'failed to verify token');
              rej('invalid_token');
            } else {
              res(decoded);
            }
          }
        );
      });
    } catch (err) {
      // TODO: set unauthenticated error before returning.
      // log invalid token.
      console.error('invalid_token', 'failed with error', err);
      return errorContext(ctx, 401);
    }

    // 3. Check if the token has been revoked.
    try {
      const revoked = await isRevoked(ctx, verifiedPayload);
      if (revoked) {
        // TODO: set 403 unauthorized before returning.
        //new UnauthorizedError('revoked_token', {message: 'The token has been revoked.'})
        console.error(
          'invalid_token',
          'provided token is valid, but has been revoked'
        );
        return errorContext(ctx, 401);
      }
    } catch (err) {
      // TODO: log before returning.
      console.error('unknown_error', err);
      return errorContext(ctx);
    }
    // Store the decoded and verified token payload in the context.
    set(ctx, outputProperty, verifiedPayload);
    return await next(ctx);
  };

  return middleware;
};
