# predix-uaa-client
Node module to get a token from UAA using client credentials or a refresh token.

## Usage
Install via npm

```
npm install --save predix-uaa-client
```

Use client credentials to get a bearer token.

NOTE: This call can be made for each outgoing request.  The library will cache the token until expiry, so subsequent calls will resolve instantaneously.

```javascript
const uaa_util = require('predix-uaa-client');
// Call with client credentials (UAAUrl, ClientID, ClientSecret),
// will fetch a client token using these credentials.
// In this case the client needs authorized_grant_types: client_credentials
uaa_util.getToken(url, clientId, clientSecret).then((token) => {
    // Use token.access_token as a Bearer token Authroization header
    // in calls to secured services.
    request.get({
        uri: 'https://secured.service.example.com',
        headers: {
            Authorization: 'Bearer ' + token.access_token
        }
    }).then((data) => {
        console.log('Got ' + data + ' from service');
    }).catch((err) => {
        console.error('Error getting data', err);
    });
}).catch((err) => {
    console.error('Error getting token', err);
});
```

Use a refresh token get a new access_token for a user.

NOTE: This will NOT cache, this should only be called when a new user access token is required.

```javascript
const uaa_util = require('predix-uaa-client');
// Call with client credentials (UAAUrl, ClientID, ClientSecret, RefreshToken),
// will fetch an access token for the user represented by the refresh token.
// In this case the client needs authorized_grant_types: refresh_token
uaa_util.getToken(url, clientId, clientSecret, refreshToken).then((token) => {
    // New access token is in token.access_token.
    // New refresh token is in token.refresh_token.
    console.log('New access token', token.access_token);
    console.log('New refresh token', token.refresh_token);
    console.log('New access token expires at', token.expire_time);
}).catch((err) => {
    console.error('Error getting token', err);
});
```
