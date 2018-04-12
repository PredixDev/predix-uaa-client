'use strict'
const expect = require('chai').expect;
const request = require('request');
const sinon = require('sinon');
const match = sinon.match;
const uaa_util = require('../index');

// ====================================================
// STUBS & HELPERS
const url = 'https://test.uaa.predix.io/oauth/token';
const clientId = 'test';
const clientSecret = 'password';
const refreshToken = 'ABC';

afterEach((done) => {
    // Undo any sinon mocks
    if(request.get.restore) request.get.restore();
    if(request.post.restore) request.post.restore();
    // Clear the token cache
    uaa_util.clearCache();
    done();
});

// ====================================================
// TESTS
describe('#UAA Tokens', () => {
    it('should be able to fetch a client token from UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token', expires_in: 123 }));

        // When called with client credentials (UAAUrl, ClientID, ClientSecret)
        // Should fetch a client token using these credentials.
        // In this case the client needs authorized_grant_types: client_credentials
        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token');
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should cache tokens', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 123 }));

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 123 }));

            // Get it again, it should not call our stub again
            uaa_util.getToken(url, clientId, clientSecret).then((token) => {
                // Stub should be called only once overall
                expect(stub.calledOnce).to.be.true;
                expect(token.access_token).to.equal('test-token-1');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });
    
    it('should clear cache by key', (done) => {
      const testCacheKey = `${url}__${clientId}`;
      // We expect a POST call with the client credentials as Basic Auth.
      let stub = sinon.stub(request, 'post');
      stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 123 }));

      uaa_util.getToken(url, clientId, clientSecret).then((token) => {
          // Result should be our fake token
          // Check that the UAA call was made correctly
          expect(stub.calledOnce).to.be.true;
          expect(stub.calledWith(match({ url }))).to.be.ok;
          expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
          expect(token.access_token).to.equal('test-token-1');

          stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 123 }));
          
          //clear the key, and should call stub again.
          uaa_util.clearCache(testCacheKey);
          
          // Get it again, it should call our stub again
          uaa_util.getToken(url, clientId, clientSecret).then((token) => {
              
              // Stub should be called twice overall
              expect(stub.calledTwice).to.be.true;
              expect(token.access_token).to.equal('test-token-2');
              done();
          }).catch((err) => {
              done(err);
          });
      }).catch((err) => {
          done(err);
      });
    });

    it('should fetch a new client token from UAA if expiring soon, but give the current one', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 10 }));

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 1000 }));

            // Get it again, it should give the first token, but still call the stub again
            uaa_util.getToken(url, clientId, clientSecret).then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token.access_token).to.equal('test-token-1');

                // Get it one more time, to prove that we got another new token
                uaa_util.getToken(url, clientId, clientSecret).then((token) => {
                    // Stub should be called twice overall
                    expect(stub.calledTwice).to.be.true;
                    // But now have the new token
                    expect(token.access_token).to.equal('test-token-2');
                    done();
                }).catch((err) => {
                    done(err);
                });

            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fetch a new client token from UAA if already expired', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 0 }));

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 1000 }));

            // Get it again, it should give us the new token
            uaa_util.getToken(url, clientId, clientSecret).then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token.access_token).to.equal('test-token-2');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fail if getting an error while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 403 }, null);

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            expect(err).to.be.an('error');
            expect(err.statusCode).to.equal(403);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should fail if no response while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, null, null);

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            expect(err).to.be.an('error');
            expect(err.statusCode).to.equal(502);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should fail if there was a network error while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(new Error('ECONNREFUSED, Connection refused'), null, null);

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            expect(err).to.be.an('error');
            expect(err.statusCode).to.equal(502);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should still return a token, if valid, even if fetching a new one has an error', (done) => {
        // Make the token appear to expire soon, but not yet
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 10 }));

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');

            // Make the next call fail
            stub.yields(null, { statusCode: 403 }, null);

            // Get it again, it should give the first token, but still call the stub again
            uaa_util.getToken(url, clientId, clientSecret).then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token.access_token).to.equal('test-token-1');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should error with missing arguments', () => {
        // Check that the error message contains the missing property
        expect(uaa_util.getToken).to.throw(/uri/);
        expect(uaa_util.getToken).to.throw(/clientId/);
        expect(uaa_util.getToken).to.throw(/clientSecret/);
    });

    it('should be able to refresh an access token from UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        // grant_type should be refresh token and refresh_token should be included
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token', expires_in: 123 }));

        // When called with a 4th arg of refreshToken (UAAUrl, ClientID, ClientSecret, refreshToken)
        // Should fetch an access token using the refresh.
        // In this case the client needs authorized_grant_types: refresh_token
        uaa_util.getToken(url, clientId, clientSecret, refreshToken).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'refresh_token' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token');
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should never cache access tokens obtained by refresh token', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        // grant_type should be refresh token and refresh_token should be included
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 123 }));

        // When called with a 4th arg of refreshToken (UAAUrl, ClientID, ClientSecret, refreshToken)
        // Should fetch an access token using the refresh.
        // In this case the client needs authorized_grant_types: refresh_token
        uaa_util.getToken(url, clientId, clientSecret, refreshToken).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'refresh_token' }}))).to.be.ok;
            expect(stub.calledWith(match({ form: { refresh_token: refreshToken }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');

            // Fake out a new token for the next request
            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 123 }));

            // Call again, should get a new token
            uaa_util.getToken(url, clientId, clientSecret, refreshToken).then((token) => {
                // Result should be our fake token
                // Check that the UAA call was made correctly
                expect(stub.calledTwice).to.be.true;
                expect(stub.calledWith(match({ url }))).to.be.ok;
                expect(stub.calledWith(match({ form: { grant_type: 'refresh_token' }}))).to.be.ok;
                expect(stub.calledWith(match({ form: { refresh_token: refreshToken }}))).to.be.ok;
                expect(token.access_token).to.equal('test-token-2');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fail to refresh if getting an error while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 401 }, null);

        uaa_util.getToken(url, clientId, clientSecret, refreshToken).then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            expect(err).to.be.an('error');
            expect(err.statusCode).to.equal(401);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should allow only one pending token request per client/refresh/host combination', (done) => {
        // Make the token generation have a short delay
        let v = 55;
        let stub = sinon.stub(request, 'post', (opt, cb) => {
            setTimeout(() => {
                cb(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-'+(v++), expires_in: 1000 }));
            }, 10);
        });

        // Multiple calls using the same url/clientId should be resolved together
        const prom1 = uaa_util.getToken(url, clientId, clientSecret);
        const prom2 = uaa_util.getToken(url, clientId, clientSecret);
        const prom3 = uaa_util.getToken(url, 'anotherUser', 'anotherPass');

        prom1.then((token1) => {
            prom2.then((token2) => {
                prom3.then((token3) => {
                    // The call should go out only twice, as 2 of the requests were the same
                    expect(stub.calledTwice).to.be.true;
                    expect(token1.access_token).to.equal('test-token-55');
                    expect(token2.access_token).to.equal('test-token-55');
                    expect(token3.access_token).to.equal('test-token-56');
                    done();
                }).catch((err) => {
                    done(err);
                });
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should expose the token type', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 123, token_type: 'bearer' }));

        uaa_util.getToken(url, clientId, clientSecret).then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ url }))).to.be.ok;
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }}))).to.be.ok;
            expect(token.access_token).to.equal('test-token-1');
            expect(token.token_type).to.equal('bearer');
            done();
        }).catch((err) => {
            done(err);
        });
    });
});
