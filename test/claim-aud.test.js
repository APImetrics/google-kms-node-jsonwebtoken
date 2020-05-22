'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

const done = () => () => null;

async function signWithAudience(audience, payload, callback) {
  const options = {algorithm: 'none'};
  if (audience !== undefined) {
    options.audience = audience;
  }

  await testUtils.signJWTHelper(payload, 'secret', options, callback);
}

async function verifyWithAudience(token, audience,  callback) {
 await testUtils.verifyJWTHelper(token, undefined, {audience}, callback);
}

describe('audience', function() {
  describe('`jwt.sign` "audience" option validation', function () {
    [
      true,
      false,
      null,
      -1,
      1,
      0,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      {},
      {foo: 'bar'},
    ].forEach((audience) => {
      it(`should error with with value ${util.inspect(audience)}`, async function () {
        await signWithAudience(audience, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"audience" must be a string or array');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {aud: undefined}
    it('should error with with value undefined', async function () {
      testUtils.signJWTHelper({}, 'secret', {audience: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"audience" must be a string or array');
        });
      });
    });

    it('should error when "aud" is in payload', async function () {
      await signWithAudience('my_aud', {aud: ''}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.audience" option. The payload already has an "aud" property.'
          );
        });
      });
    });

    it('should error with a string payload', async function () {
      await signWithAudience('my_aud', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid audience option for string payload');
        });
      });
    });

    it('should error with a Buffer payload', async function () {
      await signWithAudience('my_aud', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid audience option for object payload');
        });
      });
    });
  });

  describe('when signing and verifying a token with "audience" option', function () {
    describe('with a "aud" of "urn:foo" in payload', function () {
      let token;

      beforeEach(async () => {
        await signWithAudience('urn:foo', {}, (err, t) => {
          token = t;
          done(err);
        });
      });

      [
        undefined,
        'urn:foo',
        /^urn:f[o]{2}$/,
        ['urn:no_match', 'urn:foo'],
        ['urn:no_match', /^urn:f[o]{2}$/],
        [/^urn:no_match$/, /^urn:f[o]{2}$/],
        [/^urn:no_match$/, 'urn:foo']
      ].forEach((audience) =>{
        it(`should verify and decode with verify "audience" option of ${util.inspect(audience)}`, async function () {
          await verifyWithAudience(token, audience, (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud', 'urn:foo');
            });
          });
        });
      });

      it(`should error on no match with a string verify "audience" option`, async function () {
        await verifyWithAudience(token, 'urn:no-match', (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: urn:no-match`);
          });
        });
      });

      it('should error on no match with an array of string verify "audience" option', async function () {
        await verifyWithAudience(token, ['urn:no-match-1', 'urn:no-match-2'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2`);
          });
        });
      });

      it('should error on no match with a Regex verify "audience" option', async function () {
        await verifyWithAudience(token, /^urn:no-match$/, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: /^urn:no-match$/`);
          });
        });
      });

      it('should error on no match with an array of Regex verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match-1$/, /^urn:no-match-2$/], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property(
              'message', `jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/`
            );
          });
        });
      });

      it('should error on no match with an array of a Regex and a string in verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match$/, 'urn:no-match'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property(
              'message', `jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match`
            );
          });
        });
      });
    });

    describe('with an array of ["urn:foo", "urn:bar"] for "aud" value in payload', function () {
      let token;

      beforeEach(async () => {
        await signWithAudience(['urn:foo', 'urn:bar'], {}, (err, t) => {
          token = t;
          done(err);
        });
      });

      [
        undefined,
        'urn:foo',
        /^urn:f[o]{2}$/,
        ['urn:no_match', 'urn:foo'],
        ['urn:no_match', /^urn:f[o]{2}$/],
        [/^urn:no_match$/, /^urn:f[o]{2}$/],
        [/^urn:no_match$/, 'urn:foo']
      ].forEach((audience) =>{
        it(`should verify and decode with verify "audience" option of ${util.inspect(audience)}`, async function () {
          await verifyWithAudience(token, audience, (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });
      });

      it(`should error on no match with a string verify "audience" option`, async function () {
        await verifyWithAudience(token, 'urn:no-match', (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: urn:no-match`);
          });
        });
      });

      it('should error on no match with an array of string verify "audience" option', async function () {
        await verifyWithAudience(token, ['urn:no-match-1', 'urn:no-match-2'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2`);
          });
        });
      });

      it('should error on no match with a Regex verify "audience" option', async function () {
        await verifyWithAudience(token, /^urn:no-match$/, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', `jwt audience invalid. expected: /^urn:no-match$/`);
          });
        });
      });

      it('should error on no match with an array of Regex verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match-1$/, /^urn:no-match-2$/], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property(
              'message', `jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/`
            );
          });
        });
      });

      it('should error on no match with an array of a Regex and a string in verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match$/, 'urn:no-match'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property(
              'message', `jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match`
            );
          });
        });
      });

      describe('when checking for a matching on both "urn:foo" and "urn:bar"', function() {
        it('should verify with an array of stings verify "audience" option', async function () {
          await verifyWithAudience(token, ['urn:foo', 'urn:bar'], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with a Regex verify "audience" option', async function () {
          await verifyWithAudience(token, /^urn:[a-z]{3}$/, (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array of Regex verify "audience" option', async function () {
          await verifyWithAudience(token, [/^urn:f[o]{2}$/, /^urn:b[ar]{2}$/], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });
      });

      describe('when checking for a matching for "urn:foo"', function() {
        it('should verify with a string verify "audience"', async function () {
          await verifyWithAudience(token, 'urn:foo', (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with a Regex verify "audience" option', async function () {
          await verifyWithAudience(token, /^urn:f[o]{2}$/, (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array of Regex verify "audience"', async function () {
          await verifyWithAudience(token, [/^urn:no-match$/, /^urn:f[o]{2}$/], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array containing a string and a Regex verify "audience" option', async function () {
          await verifyWithAudience(token, ['urn:no_match', /^urn:f[o]{2}$/], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array containing a Regex and a string verify "audience" option', async function () {
          await verifyWithAudience(token, [/^urn:no-match$/, 'urn:foo'], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });
      });

      describe('when checking matching for "urn:bar"', function() {
        it('should verify with a string verify "audience"', async function () {
          await verifyWithAudience(token, 'urn:bar', (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with a Regex verify "audience" option', async function () {
          await verifyWithAudience(token, /^urn:b[ar]{2}$/, (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array of Regex verify "audience" option', async function () {
          await verifyWithAudience(token, [/^urn:no-match$/, /^urn:b[ar]{2}$/], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array containing a string and a Regex verify "audience" option', async function () {
          await verifyWithAudience(token, ['urn:no_match', /^urn:b[ar]{2}$/], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });

        it('should verify with an array containing a Regex and a string verify "audience" option', async function () {
          await verifyWithAudience(token, [/^urn:no-match$/, 'urn:bar'], (err, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(err).to.be.null;
              expect(decoded).to.have.property('aud').deep.equals(['urn:foo', 'urn:bar']);
            });
          });
        });
      });
    });

    describe('without a "aud" value in payload', function () {
      let token;

      beforeEach(async () => {
        await signWithAudience(undefined, {}, (err, t) => {
          token = t;
          done(err);
        });
      });

      it('should verify and decode without verify "audience" option', async function () {
        await verifyWithAudience(token, undefined, (err, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.null;
            expect(decoded).to.not.have.property('aud');
          });
        });
      });

      it('should error on no match with a string verify "audience" option', async function () {
        await verifyWithAudience(token, 'urn:no-match', (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'jwt audience invalid. expected: urn:no-match');
          });
        });
      });

      it('should error on no match with an array of string verify "audience" option', async function () {
        await verifyWithAudience(token, ['urn:no-match-1', 'urn:no-match-2'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2');
          });
        });
      });

      it('should error on no match with a Regex verify "audience" option', async function () {
        await verifyWithAudience(token, /^urn:no-match$/, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'jwt audience invalid. expected: /^urn:no-match$/');
          });
        });
      });

      it('should error on no match with an array of Regex verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match-1$/, /^urn:no-match-2$/], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/');
          });
        });
      });

      it('should error on no match with an array of a Regex and a string in verify "audience" option', async function () {
        await verifyWithAudience(token, [/^urn:no-match$/, 'urn:no-match'], (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match');
          });
        });
      });
    });
  });
});
