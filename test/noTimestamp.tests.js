var jwt = require('../index');
var expect = require('chai').expect;

describe('noTimestamp', function() {

  it('should work with string', async function () {
    var token = await jwt.sign({foo: 123}, '123', { expiresIn: '5m' , noTimestamp: true });
    var result = await jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + (5*60), 0.5);
  });

});
