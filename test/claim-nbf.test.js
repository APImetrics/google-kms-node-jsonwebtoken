'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

const done = () => () => null;

async function signWithNotBefore(notBefore, payload, callback) {
  const options = {algorithm: 'none'};
  if (notBefore !== undefined) {
    options.notBefore = notBefore;
  }
  await testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('not before', function() {
  describe('`jwt.sign` "notBefore" option validation', function () {
    [
      true,
      false,
      null,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((notBefore) => {
      it(`should error with with value ${util.inspect(notBefore)}`, async function () {
        await signWithNotBefore(notBefore, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message')
              .match(/"notBefore" should be a number of seconds or string representing a timespan/);
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {notBefore: undefined}
    it('should error with with value undefined', async function () {
      testUtils.signJWTHelper({}, undefined, {notBefore: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            '"notBefore" should be a number of seconds or string representing a timespan'
          );
        });
      });
    });

    it('should error when "nbf" is in payload', async function () {
      await signWithNotBefore(100, {nbf: 100}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.notBefore" option the payload already has an "nbf" property.'
          );
        });
      });
    });

    it('should error with a string payload', async function () {
      await signWithNotBefore(100, 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid notBefore option for string payload');
        });
      });
    });

    it('should error with a Buffer payload', async function () {
      await signWithNotBefore(100, new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid notBefore option for object payload');
        });
      });
    });
  });

  describe('`jwt.sign` "nbf" claim validation', function () {
    [
      true,
      false,
      null,
      undefined,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, async function () {
        await signWithNotBefore(undefined, {nbf}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"nbf" should be a number of seconds');
          });
        });
      });
    });
  });

  describe('"nbf" in payload validation', function () {
    [
      true,
      false,
      null,
      -Infinity,
      Infinity,
      NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, async function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({nbf}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        await testUtils.verifyJWTHelper(token, undefined, {nbf}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'invalid nbf value');
          });
        });
      });
    })
  });

  describe('when signing and verifying a token with "notBefore" option', function () {
    let fakeClock;
    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function () {
      fakeClock.uninstall();
    });

    it('should set correct "nbf" with negative number of seconds', async function () {
      await signWithNotBefore(-10, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 50);
          });
        })
      });
    });

    it('should set correct "nbf" with positive number of seconds', async function () {
      await signWithNotBefore(10, {}, async (e1, token) => {
        fakeClock.tick(10000);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 70);
          });
        })
      });
    });

    it('should set correct "nbf" with zero seconds', async function () {
      await signWithNotBefore(0, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 60);
          });
        })
      });
    });

    it('should set correct "nbf" with negative string timespan', async function () {
      await signWithNotBefore('-10 s', {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 50);
          });
        })
      });
    });

    it('should set correct "nbf" with positive string timespan', async function () {
      await signWithNotBefore('10 s', {}, async (e1, token) => {
        fakeClock.tick(10000);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 70);
          });
        })
      });
    });

    it('should set correct "nbf" with zero string timespan', async function () {
      await signWithNotBefore('0 s', {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 60);
          });
        })
      });
    });

    // TODO an nbf of -Infinity should fail validation
    it('should set null "nbf" when given -Infinity', async function () {
      await signWithNotBefore(undefined, {nbf: -Infinity}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('nbf', null);
        });
      });
    });

    // TODO an nbf of Infinity should fail validation
    it('should set null "nbf" when given value Infinity', async function () {
      await signWithNotBefore(undefined, {nbf: Infinity}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('nbf', null);
        });
      });
    });

    // TODO an nbf of NaN should fail validation
    it('should set null "nbf" when given value NaN', async function () {
      await signWithNotBefore(undefined, {nbf: NaN}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('nbf', null);
        });
      });
    });

    it('should set correct "nbf" when "iat" is passed', async function () {
      await signWithNotBefore(-10, {iat: 40}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('nbf', 30);
          });
        })
      });
    });

    it('should verify "nbf" using "clockTimestamp"', async function () {
      await signWithNotBefore(10, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {clockTimestamp: 70}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('nbf', 70);
          });
        })
      });
    });

    it('should verify "nbf" using "clockTolerance"', async function () {
      await signWithNotBefore(5, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {clockTolerance: 6}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('nbf', 65);
          });
        })
      });
    });

    it('should ignore a not active token when "ignoreNotBefore" is true', async function () {
      await signWithNotBefore('10 s', {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {ignoreNotBefore: true}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('nbf', 70);
          });
        })
      });
    });

    it('should error on verify if "nbf" is after current time', async function () {
      await signWithNotBefore(undefined, {nbf: 61}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.NotBeforeError);
            expect(e2).to.have.property('message', 'jwt not active');
          });
        })
      });
    });

    it('should error on verify if "nbf" is after current time using clockTolerance', async function () {
      await signWithNotBefore(5, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {clockTolerance: 4}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.NotBeforeError);
            expect(e2).to.have.property('message', 'jwt not active');
          });
        })
      });
    });
  });
});