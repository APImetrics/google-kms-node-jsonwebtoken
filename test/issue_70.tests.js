var jwt = require('../');

describe('issue 70 - public key start with BEING PUBLIC KEY', function () {

  it('should work', async function () {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var token = await jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    await jwt.verify(token, cert_pub);
  });

});