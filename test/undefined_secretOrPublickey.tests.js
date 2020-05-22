var jwt = require('../index');
var JsonWebTokenError = require('../lib/JsonWebTokenError');
var chai = require('chai');
var expect = chai.expect;
chai.use(require('chai-as-promised'))

var TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M';

describe('verifying without specified secret or public key', function () {
  it('should not verify null', async function () {
    await expect(
      jwt.verify(TOKEN, null)
    ).to.be.rejectedWith(JsonWebTokenError, /secret or public key must be provided/);
  });

  it('should not verify undefined', async function () {
    await expect(
      jwt.verify(TOKEN)
    ).to.be.rejectedWith(JsonWebTokenError, /secret or public key must be provided/);
  });
});