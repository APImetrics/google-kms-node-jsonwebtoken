'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

const done = () => () => null;

function signWithIssuer(issuer, payload, callback) {
  const options = {algorithm: 'none'};
  if (issuer !== undefined) {
    options.issuer = issuer;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('issuer', function() {
  describe('`jwt.sign` "issuer" option validation', function () {
    [
      true,
      false,
      null,
      -1,
      0,
      1,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((issuer) => {
      it(`should error with with value ${util.inspect(issuer)}`, async function () {
        await signWithIssuer(issuer, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"issuer" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {issuer: undefined}
    it('should error with with value undefined', async function () {
      testUtils.signJWTHelper({}, undefined, {issuer: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"issuer" must be a string');
        });
      });
    });

    it('should error when "iss" is in payload', async function () {
      await signWithIssuer('foo', {iss: 'bar'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.issuer" option. The payload already has an "iss" property.'
          );
        });
      });
    });

    it('should error with a string payload', async function () {
      await signWithIssuer('foo', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid issuer option for string payload'
          );
        });
      });
    });

    it('should error with a Buffer payload', async function () {
      await signWithIssuer('foo', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid issuer option for object payload'
          );
        });
      });
    });
  });

  describe('when signing and verifying a token', function () {
    it('should not verify "iss" if verify "issuer" option not provided', async function () {
      await signWithIssuer(undefined, {iss: 'foo'}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iss', 'foo');
          });
        })
      });
    });

    describe('with string "issuer" option', function () {
      it('should verify with a string "issuer"', async function () {
        await signWithIssuer('foo', {}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('iss', 'foo');
            });
          })
        });
      });

      it('should verify with a string "iss"', async function () {
        await signWithIssuer(undefined, {iss: 'foo'}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('iss', 'foo');
            });
          })
        });
      });

      it('should error if "iss" does not match verify "issuer" option', async function() {
        await signWithIssuer(undefined, {iss: 'foobar'}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt issuer invalid. expected: foo');
            });
          })
        });
      });

      it('should error without "iss" and with verify "issuer" option', async function () {
        await signWithIssuer(undefined, {}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt issuer invalid. expected: foo');
            });
          })
        });
      });
    });

    describe('with array "issuer" option', function () {
      it('should verify with a string "issuer"', async function () {
        await signWithIssuer('bar', {}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('iss', 'bar');
            });
          })
        });
      });

      it('should verify with a string "iss"', async function () {
        await signWithIssuer(undefined, {iss: 'foo'}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('iss', 'foo');
            });
          })
        });
      });

      it('should error if "iss" does not match verify "issuer" option', async function () {
        await signWithIssuer(undefined, {iss: 'foobar'}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt issuer invalid. expected: foo,bar');
            });
          })
        });
      });

      it('should error without "iss" and with verify "issuer" option', async function() {
        await signWithIssuer(undefined, {}, async (e1, token) => {
          await testUtils.verifyJWTHelper(token, undefined, {issuer: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt issuer invalid. expected: foo,bar');
            });
          })
        });
      });
    });
  });
});
