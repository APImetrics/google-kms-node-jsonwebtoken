var jwt = require('../index');
var chai = require('chai');
var expect = chai.expect;
chai.use(require('chai-as-promised'));

describe('expires option', function() {

  it('should throw on deprecated expiresInSeconds option', async () => {
    await expect(
      jwt.sign({foo: 123}, '123', { expiresInSeconds: 5 })
    ).to.be.rejectedWith('"expiresInSeconds" is not allowed');
  });

});
