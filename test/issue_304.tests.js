var jwt = require('../index');
var expect = require('chai').expect;

describe('issue 304 - verifying values other than strings', function() {

  it('should fail with numbers', async function () {
    await jwt.verify(123, 'foo', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
      // done();
    });
  });

  it('should fail with objects', async function () {
    await jwt.verify({ foo: 'bar' }, 'biz', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
      // done();
    });
  });

  it('should fail with arrays', async function () {
    await jwt.verify(['foo'], 'bar', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
      // done();
    });
  });

  it('should fail with functions', async function () {
    await jwt.verify(function() {}, 'foo', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
      // done();
    });
  });

  it('should fail with booleans', async function () {
    await jwt.verify(true, 'foo', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
      // done();
    });
  });

});
