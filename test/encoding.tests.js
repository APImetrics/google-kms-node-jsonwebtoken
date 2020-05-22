var jwt = require('../index');
var expect = require('chai').expect;
var atob = require('atob');

describe('encoding', function() {

  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should properly encode the token (utf8)', async function () {
    var expected = 'José';
    var token = await jwt.sign({ name: expected }, 'shhhhh');
    var decoded_name = JSON.parse(b64_to_utf8(token.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should properly encode the token (binary)', async function () {
    var expected = 'José';
    var token = await jwt.sign({ name: expected }, 'shhhhh', { encoding: 'binary' });
    var decoded_name = JSON.parse(atob(token.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should return the same result when decoding', async function () {
    var username = '測試';

    var token = await jwt.sign({
      username: username
    }, 'test');

    var payload = await jwt.verify(token, 'test');

    expect(payload.username).to.equal(username);
  });

});
