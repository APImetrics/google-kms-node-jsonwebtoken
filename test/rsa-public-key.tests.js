var jwt = require('../');
var PS_SUPPORTED = require('../lib/psSupported');

describe('public key start with BEGIN RSA PUBLIC KEY', function () {

  it('should work for RS family of algorithms', async () => {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var token = await jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    await jwt.verify(token, cert_pub);
  });

  if (PS_SUPPORTED) {
    it('should work for PS family of algorithms', async () => {
      var fs = require('fs');
      var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
      var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

      var token = await jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'PS256'});

      await jwt.verify(token, cert_pub);
    });
  }

});
