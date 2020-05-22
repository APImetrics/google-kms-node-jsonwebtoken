var jwt = require('../index');
var expect = require('chai').expect;

describe('non_object_values values', function() {

  it('should work with string', async function () {
    var token = await jwt.sign('hello', '123');
    var result = await jwt.verify(token, '123');
    expect(result).to.equal('hello');
  });

  it('should work with number', async function () {
    var token = await jwt.sign(123, '123');
    var result = await jwt.verify(token, '123');
    expect(result).to.equal('123');
  });

});
