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

import { faas } from "@nitric/sdk";
import { get } from 'lodash';

export interface AuthorizeOptions {
  /**
   * The path in the ctx to where the user scopes can be found.
   * 
   * lodash get is used, enabling nested properties to be retrieved.
   * 
   * @default 'user.scopes';
   */
  scopesProperty?: string;
  /**
   * If true, all expectedScopes must be present in the users scope to pass authentication.
   * If false, one or more of the expectedScopes must be present in the users scope to pass authentication.
   * 
   * @default true
   */
  requireAll?: boolean;
  /**
   * If the scopes value is a string, this separator will be used to split the string.
   * 
   * Note: if the scopes are already an array this value will be ignored.
   * 
   * @default ' ''
   */
  scopeSeparator?: string;
}

const defaultOptions: AuthorizeOptions = {
  scopesProperty: 'user.scopes',
  requireAll: true,
  scopeSeparator: " ",
};

/**
 * Generate a new middleware function to check permissions (scopes) from the ctx.
 * 
 * @param expected the expected scopes required to pass authorization.
 * @param options configuration options for the produced middleware function
 * @returns a Nitric SDK HttpMiddleware function
 */
export const jwtScopes = (expected: string | string[], options: AuthorizeOptions = {}):faas.HttpMiddleware => {
  const requiredScopes: string[] = typeof expected === 'string' ? [expected] : expected;
  if (!Array.isArray(requiredScopes)) {
    throw new Error(
      'Parameter expected must be a string or an array of strings representing the scopes required for authorization.'
    );
  }

  const {scopesProperty, requireAll, scopeSeparator} = {...defaultOptions, ...options};
  if(typeof scopesProperty !== 'string' || scopesProperty === '') {
    throw new Error('Option scopesProperty must be a non-blank string');
  }

  return async (ctx, next) => {
    const error = () => {
      ctx.res.status = 403;
      return ctx;
    };

    const scopes = get(ctx, scopesProperty);

    if(!scopes) {
      console.log(`scopes value not found in ctx.${scopesProperty}`);
      return error();
    }

    let userScopes;
    if(typeof scopes === 'string') {
      userScopes = scopes.split(scopeSeparator);
    } else if(Array.isArray(scopes)) {
      userScopes = scopes;
    } else {
      console.log(`ctx.${scopesProperty} has unexpected type ${typeof scopes}`);
      return error();
    }

    // Validate the scopes based on whether they're all required or just one is required.
    let authorized
    if (requireAll) {
      authorized = requiredScopes.every(scope => userScopes.includes(scope));
    } else {
      authorized = requiredScopes.some(scope => userScopes.includes(scope));
    }

    if (!authorized) {
      return error();
    }
    return await next(ctx);
  };
};