'use strict'
const request = require('request');
const url = require('url');
const debug = require('debug')('predix-uaa-client');

const renew_secs_before = 60;

// This is what we'll export, so we can call getToken as a function nicely.
let uaa_utils = {};

// This will cache access tokens that have been granted via client_credentials.
// This is to avoid complexity of token users from having to check expiry time
// so they can simply call getToken every time to ensure they have a valid token.
// Access tokens from refresh tokens will NOT be cached in this way.  The responsibility
// of calling getToken to refresh in on the consumer.
// This design is because the 2 types of tokens are for different purposes.
// client_credentials are used for app-to-app communications, so we can cache these
// safely as a helper to the consumer without potentially keeping a token around
// for longer than a user session.
// authorization_code (i.e. refresh_token) are used for authenticated users.  The
// app may legitimately destroy a user's session.  This module should not be dealing
// with that, so the app has to be responsible for calling getToken with the refreshToken
// as and when necessary.
let client_token_cache = {};

/**
 * This function provides 2 modes of operation.
 *
 * 1. 3 args.
 *   This will fetch and cache an access token for the provided UAA client.
 *   If there is already a token which has not expired, that will be returned immediately.
 *
 * 2. 4 args.
 *   This will use the client credentials and the provided refresh token to get a new
 *   access token using the refresh token.  Access tokens will NOT be cached in this mode.
 *
 *
 * @returns {promise} - A promise to provide a token.
 *                      Resolves with the token if successful (or already available).
 *                      Rejected with an error if an error occurs.
 */
uaa_utils.getToken = (uaaUri, clientId, clientSecret, refreshToken) => {

    // Throw exception if required options are missing
    let missingArgs = [];
    if(!uaaUri) missingArgs.push('uaa.uri');
    if(!clientId) missingArgs.push('uaa.clientId');
    if(!clientSecret) missingArgs.push('uaa.clientSecret');

    if(missingArgs.length > 0) {
        const msg = 'Required argument(s) missing: ' + missingArgs.join();
        debug(msg);
        throw new Error(msg);
    }

    // URL for the token is <UAA_Server>/oauth/token
    return new Promise((resolve, reject) => {

        let alreadyResolved = false;
        let cacheable = false;
        const cache_key = `${uaaUri}__${clientId}`;
        let access_token = null;
        let form = {};
        const now = Date.now();

        // What 'mode' are we in?
        if(refreshToken) {
            // Refresh token, don't look in the cache.
            // Set the form body of the request.
            form.grant_type = 'refresh_token';
            form.refresh_token = refreshToken;
            cacheable = false;
        } else {
            // Client credentials.
            // Check the cache and pre-set the form body in case we need it.
            // Check for a current token
            access_token = client_token_cache[cache_key];
            if(access_token && access_token.expire_time > now) {
                // Already have it.
                resolve(access_token);
                alreadyResolved = true;
            }

            form.grant_type = 'client_credentials';
            cacheable = true;
        }

        // Should we get a new token?
        // If we don't have one, or ours is expiring soon, then yes!
        if(!access_token || access_token.renew_time < now) {
            // Yep, don't have one, or this one will expire soon.
            debug('Fetching new token');
            const options = {
                url: uaaUri,
                headers: {
                    'cache-control': 'no-cache',
                    'content-type': 'application/x-www-form-urlencoded'
                },
                auth: {
                    username: clientId,
                    password: clientSecret
                },
                form: form
            };

            request.post(options, (err, resp, body) => {
                const statusCode = (resp) ? resp.statusCode : 502;
                if(err || statusCode !== 200) {
                    err = err || 'Error getting token: ' + statusCode;
                    debug('Error getting token from', options.url, err);

                    // If we responded with a cached token, don't throw the error
                    if(!alreadyResolved) {
                        reject(err);
                    }
                } else {
                    debug('Fetched new token');
                    const data = JSON.parse(body);

                    // Extract the token and expires duration
                    const newToken = {
                        access_token: data.access_token,
                        expire_time: now + (data.expires_in * 1000),
                        renew_time: now + ((data.expires_in - renew_secs_before) * 1000),
                        refresh_token: data.refresh_token
                    };

                    access_token = newToken;
                    // If we responded with a cached token, don't resolve again
                    if(!alreadyResolved) {
                        resolve(access_token);
                    }

                    if(cacheable) {
                        client_token_cache[cache_key] = access_token;
                        debug('Cached new access_token for', clientId);
                    }
                }
            });
        }
    });
}

/**
 *  This function clears all the cached access tokens.
 *  Subsequent calls to getToken will fetch a new token from UAA.
 */
uaa_utils.clearCache = () => {
    client_token_cache = {};
    debug('Cleared token cache');
}

module.exports = uaa_utils;
