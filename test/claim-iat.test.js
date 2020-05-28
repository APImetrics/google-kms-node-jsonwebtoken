'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

const done = () => () => null;

async function signWithIssueAt(issueAt, options, callback) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  // async calls require a truthy secret
  // see: https://github.com/brianloveswords/node-jws/issues/62
  await testUtils.signJWTHelper(payload, 'secret', opts, callback);
}

async function verifyWithIssueAt(token, maxAge, options, callback) {
  const opts = Object.assign({maxAge}, options);
  await testUtils.verifyJWTHelper(token, undefined, opts, callback);
}

describe('issue at', function() {
  describe('`jwt.sign` "iat" claim validation', function () {
    [
      true,
      false,
      null,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with iat of ${util.inspect(iat)}`, async function () {
        await signWithIssueAt(iat, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err.message).to.equal('"iat" should be a number of seconds');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {iat: undefined}
    it('should error with iat of undefined', async function () {
      await testUtils.signJWTHelper({iat: undefined}, 'secret', {algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err.message).to.equal('"iat" should be a number of seconds');
        });
      });
    });
  });

  describe('"iat" in payload with "maxAge" option validation', function () {
    [
      true,
      false,
      null,
      undefined,
      -Infinity,
      Infinity,
      NaN,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with iat of ${util.inspect(iat)}`, async function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({iat}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        verifyWithIssueAt(token, '1 min', {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err.message).to.equal('iat required when maxAge is specified');
          });
        });
      });
    })
  });

  describe('when signing a token', function () {
    let fakeClock;
    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function () {
      fakeClock.uninstall();
    });

    [
      {
        description: 'should default to current time for "iat"',
        iat: undefined,
        expectedIssueAt: 60,
        options: {}
      },
      {
        description: 'should sign with provided time for "iat"',
        iat: 100,
        expectedIssueAt: 100,
        options: {}
      },
      // TODO an iat of -Infinity should fail validation
      {
        description: 'should set null "iat" when given -Infinity',
        iat: -Infinity,
        expectedIssueAt: null,
        options: {}
      },
      // TODO an iat of Infinity should fail validation
      {
        description: 'should set null "iat" when given Infinity',
        iat: Infinity,
        expectedIssueAt: null,
        options: {}
      },
      // TODO an iat of NaN should fail validation
      {
        description: 'should set to current time for "iat" when given value NaN',
        iat: NaN,
        expectedIssueAt: 60,
        options: {}
      },
      {
        description: 'should remove default "iat" with "noTimestamp" option',
        iat: undefined,
        expectedIssueAt: undefined,
        options: {noTimestamp: true}
      },
      {
        description: 'should remove provided "iat" with "noTimestamp" option',
        iat: 10,
        expectedIssueAt: undefined,
        options: {noTimestamp: true}
      },
    ].forEach((testCase) => {
      it(testCase.description, async function () {
        let tokenOut = null;
        await signWithIssueAt(testCase.iat, testCase.options, (err, token) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.null;
            tokenOut = token;
          });
        });
        expect(tokenOut).to.not.be.null;
        const decoded = await jwt.decode(tokenOut);
        expect(decoded.iat).to.equal(testCase.expectedIssueAt);
      });
    });
  });

  describe('when verifying a token', function() {
    let fakeClock;

    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function () {
      fakeClock.uninstall();
    });

    [
      {
        description: 'should verify using "iat" before the "maxAge"',
        clockAdvance: 10000,
        maxAge: 11,
        options: {},
      },
      {
        description: 'should verify using "iat" before the "maxAge" with a provided "clockTimestamp',
        clockAdvance: 60000,
        maxAge: 11,
        options: {clockTimestamp: 70},
      },
      {
        description: 'should verify using "iat" after the "maxAge" but within "clockTolerance"',
        clockAdvance: 10000,
        maxAge: 9,
        options: {clockTimestamp: 2},
      },
    ].forEach((testCase) => {
      it(testCase.description, async function () {
        const token = await jwt.sign({}, 'secret', {algorithm: 'none'});
        fakeClock.tick(testCase.clockAdvance);
        verifyWithIssueAt(token, testCase.maxAge, testCase.options, (err, token) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.null;
            expect(token).to.be.a('object');
          });
        });
      });
    });

    [
      {
        description: 'should throw using "iat" equal to the "maxAge"',
        clockAdvance: 10000,
        maxAge: 10,
        options: {},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 70000,
      },
      {
        description: 'should throw using "iat" after the "maxAge"',
        clockAdvance: 10000,
        maxAge: 9,
        options: {},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 69000,
      },
      {
        description: 'should throw using "iat" after the "maxAge" with a provided "clockTimestamp',
        clockAdvance: 60000,
        maxAge: 10,
        options: {clockTimestamp: 70},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 70000,
      },
      {
        description: 'should throw using "iat" after the "maxAge" and "clockTolerance',
        clockAdvance: 10000,
        maxAge: 8,
        options: {clockTolerance: 2},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 68000,
      },
    ].forEach((testCase) => {
      it(testCase.description, async function () {
        const expectedExpiresAtDate = new Date(testCase.expectedExpiresAt);
        const token = await jwt.sign({}, 'secret', {algorithm: 'none'});
        fakeClock.tick(testCase.clockAdvance);

        verifyWithIssueAt(token, testCase.maxAge, testCase.options, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err.message).to.equal(testCase.expectedError);
            expect(err.expiredAt).to.deep.equal(expectedExpiresAtDate);
          });
        });
      });
    });
  });

  describe('with string payload', function () {
    it('should not add iat to string', async function () {
      const payload = 'string payload';
      const options = {algorithm: 'none'};
      await testUtils.signJWTHelper(payload, 'secret', options, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.equal(payload);
        });
      });
    });

    it('should not add iat to stringified object', async function () {
      const payload = '{}';
      const options = {algorithm: 'none', header: {typ: 'JWT'}};
      await testUtils.signJWTHelper(payload, 'secret', options, async (err, token) => {
        const decoded = await jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.equal(null);
          expect(JSON.stringify(decoded)).to.equal(payload);
        });
      });
    });
  });
});
