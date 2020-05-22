var jwt = require("../.");
var assert = require('chai').assert;

describe('buffer payload', function () {
  it('should work', async function () {
    var payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');
    var token = await jwt.sign(payload, "signing key");
    assert.equal(await jwt.decode(token), payload.toString());
  });
});
