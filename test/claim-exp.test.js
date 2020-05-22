'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

const done = () => () => null;

async function signWithExpiresIn(expiresIn, payload, callback) {
  const options = {algorithm: 'none'};
  if (expiresIn !== undefined) {
    options.expiresIn = expiresIn;
  }
  await testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('expires', function() {
  describe('`jwt.sign` "expiresIn" option validation', function () {
    [
      true,
      false,
      null,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      ' ',
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((expiresIn) => {
      it(`should error with with value ${util.inspect(expiresIn)}`, async function () {
        await signWithExpiresIn(expiresIn, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message')
              .match(/"expiresIn" should be a number of seconds or string representing a timespan/);
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {expiresIn: undefined}
    it('should error with with value undefined', async function () {
      await testUtils.signJWTHelper({}, undefined, {expiresIn: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            '"expiresIn" should be a number of seconds or string representing a timespan'
          );
        });
      });
    });

    it('should error when "exp" is in payload', async function() {
      await signWithExpiresIn(100, {exp: 100}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.expiresIn" option the payload already has an "exp" property.'
          );
        });
      });
    });

    it('should error with a string payload', async function() {
      await signWithExpiresIn(100, 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid expiresIn option for string payload');
        });
      });
    });

    it('should error with a Buffer payload', async function() {
      await signWithExpiresIn(100, Buffer.from('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid expiresIn option for object payload');
        });
      });
    });
  });

  describe('`jwt.sign` "exp" claim validation', function () {
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
    ].forEach((exp) => {
      it(`should error with with value ${util.inspect(exp)}`, async function () {
        await signWithExpiresIn(undefined, {exp}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"exp" should be a number of seconds');
          });
        });
      });
    });
  });

  describe('"exp" in payload validation', function () {
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
    ].forEach((exp) => {
      it(`should error with with value ${util.inspect(exp)}`, async function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({exp}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        await testUtils.verifyJWTHelper(token, undefined, {exp}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'invalid exp value');
          });
        });
      });
    })
  });

  describe('when signing and verifying a token with expires option', function () {
    let fakeClock;
    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function() {
      fakeClock.uninstall();
    });

    it('should set correct "exp" with negative number of seconds', async function() {
      await signWithExpiresIn(-10, {}, async (e1, token) => {
        fakeClock.tick(-10001);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should set correct "exp" with positive number of seconds', async function() {
      await signWithExpiresIn(10, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should set correct "exp" with zero seconds', async function() {
      await signWithExpiresIn(0, {}, async (e1, token) => {
        fakeClock.tick(-1);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 60);
          });
        })
      });
    });

    it('should set correct "exp" with negative string timespan', async function() {
      await signWithExpiresIn('-10 s', {}, async (e1, token) => {
        fakeClock.tick(-10001);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should set correct "exp" with positive string timespan', async function() {
      await signWithExpiresIn('10 s', {}, async (e1, token) => {
        fakeClock.tick(-10001);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should set correct "exp" with zero string timespan', async function() {
      await signWithExpiresIn('0 s', {}, async (e1, token) => {
        fakeClock.tick(-1);
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 60);
          });
        })
      });
    });

    // TODO an exp of -Infinity should fail validation
    it('should set null "exp" when given -Infinity', async function () {
      await signWithExpiresIn(undefined, {exp: -Infinity}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    // TODO an exp of Infinity should fail validation
    it('should set null "exp" when given value Infinity', async function () {
      await signWithExpiresIn(undefined, {exp: Infinity}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    // TODO an exp of NaN should fail validation
    it('should set null "exp" when given value NaN', async function () {
      await signWithExpiresIn(undefined, {exp: NaN}, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    it('should set correct "exp" when "iat" is passed', async function () {
      await signWithExpiresIn(-10, {iat: 80}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should verify "exp" using "clockTimestamp"', async function () {
      await signWithExpiresIn(10, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {clockTimestamp: 69}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should verify "exp" using "clockTolerance"', async function () {
      await signWithExpiresIn(5, {}, async (e1, token) => {
        fakeClock.tick(10000);
        await testUtils.verifyJWTHelper(token, undefined, {clockTimestamp: 6}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 65);
          });
        })
      });
    });

    it('should ignore a expired token when "ignoreExpiration" is true', async function () {
      await signWithExpiresIn('-10 s', {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {ignoreExpiration: true}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should error on verify if "exp" is at current time', async function() {
      await signWithExpiresIn(undefined, {exp: 60}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.TokenExpiredError);
            expect(e2).to.have.property('message', 'jwt expired');
          });
        });
      });
    });

    it('should error on verify if "exp" is before current time using clockTolerance', async function () {
      await signWithExpiresIn(-5, {}, async (e1, token) => {
        await testUtils.verifyJWTHelper(token, undefined, {clockTolerance: 5}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.TokenExpiredError);
            expect(e2).to.have.property('message', 'jwt expired');
          });
        });
      });
    });
  });
});
