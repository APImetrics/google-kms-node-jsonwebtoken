'use strict';

const jwt = require('../');
var chai = require('chai');
chai.use(require('chai-as-promised'))
const sinon = require('sinon');
const util = require('util');
var expect = chai.expect;

describe('maxAge option', function() {
  let token;

  let fakeClock;
  beforeEach(async function() {
    fakeClock = sinon.useFakeTimers({now: 60000});
    token = await jwt.sign({iat: 70}, undefined, {algorithm: 'none'});
  });

  afterEach(function() {
    fakeClock.uninstall();
  });

  [
    {
      description: 'should work with a positive string value',
      maxAge: '3s',
    },
    {
      description: 'should work with a negative string value',
      maxAge: '-3s',
    },
    {
      description: 'should work with a positive numeric value',
      maxAge: 3,
    },
    {
      description: 'should work with a negative numeric value',
      maxAge: -3,
    },
  ].forEach((testCase) => {
    it(testCase.description, async () => {
      expect(await jwt.verify(token, undefined, {maxAge: '3s'})).to.not.throw;
      await jwt.verify(token, undefined, {maxAge: testCase.maxAge}, (err) => {
        expect(err).to.be.null;
        // done();
      })
    });
  });

  [
    true,
    'invalid',
    [],
    ['foo'],
    {},
    {foo: 'bar'},
  ].forEach((maxAge) => {
    it(`should error with value ${util.inspect(maxAge)}`, async () => {
      await expect(
        jwt.verify(token, undefined, {maxAge})
      ).to.be.rejectedWith(
        jwt.JsonWebTokenError,
        '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
      );
      await jwt.verify(token, undefined, {maxAge}, (err) => {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal(
          '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        );
        // done();
      })
    });
  });
});
