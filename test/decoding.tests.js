var jwt = require('../index');
var expect = require('chai').expect;

describe('decoding', function() {

  it('should not crash when decoding a null token', async function () {
    var decoded = await jwt.decode("null");
    expect(decoded).to.equal(null);
  });

});
