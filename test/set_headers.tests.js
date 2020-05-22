var jwt = require('../index');
var expect = require('chai').expect;

describe('set header', function() {

  it('should add the header', async function () {
    var token = await jwt.sign({foo: 123}, '123', { header: { foo: 'bar' } });
    var decoded = await jwt.decode(token, {complete: true});
    expect(decoded.header.foo).to.equal('bar');
  });

  it('should allow overriding header', async function () {
    var token = await jwt.sign({foo: 123}, '123', { header: { alg: 'HS512' } });
    var decoded = await jwt.decode(token, {complete: true});
    expect(decoded.header.alg).to.equal('HS512');
  });

});
