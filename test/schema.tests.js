var jwt = require('../index');
var chai = require('chai');
var fs = require('fs');
var PS_SUPPORTED = require('../lib/psSupported');
var expect = chai.expect;
chai.use(require('chai-as-promised'))

describe('schema', function() {

  describe('sign options', function() {

    var cert_rsa_priv = fs.readFileSync(__dirname + '/rsa-private.pem');
    var cert_ecdsa_priv = fs.readFileSync(__dirname + '/ecdsa-private.pem');

    async function sign(options) {
      var isEcdsa = options.algorithm && options.algorithm.indexOf('ES') === 0;
      await jwt.sign({foo: 123}, isEcdsa ? cert_ecdsa_priv : cert_rsa_priv, options);
    }

    it('should validate algorithm', async function () {
      await expect(
        sign({ algorithm: 'foo' })
      ).to.be.rejectedWith(/"algorithm" must be a valid string enum value/);
      await sign({algorithm: 'RS256'});
      await sign({algorithm: 'RS384'});
      await sign({algorithm: 'RS512'});
      if (PS_SUPPORTED) {
        await sign({algorithm: 'PS256'});
        await sign({algorithm: 'PS384'});
        await sign({algorithm: 'PS512'});
      }
      await sign({algorithm: 'ES256'});
      await sign({algorithm: 'ES384'});
      await sign({algorithm: 'ES512'});
      await sign({algorithm: 'HS256'});
      await sign({algorithm: 'HS384'});
      await sign({algorithm: 'HS512'});
      await sign({algorithm: 'none'});
    });

    it('should validate header', async function () {
      expect(
        sign({ header: 'foo' })
      ).to.be.rejectedWith(/"header" must be an object/);
      await sign({header: {}});
    });

    it('should validate encoding', async function () {
      expect(
        sign({ encoding: 10 })
      ).to.be.rejectedWith(/"encoding" must be a string/);
      await sign({encoding: 'utf8'});
    });

    it('should validate noTimestamp', async function () {
      expect(
        sign({ noTimestamp: 10 })
      ).to.be.rejectedWith(/"noTimestamp" must be a boolean/);
      await sign({noTimestamp: true});
    });
  });

  describe('sign payload registered claims', function() {

    async function sign(payload) {
      await jwt.sign(payload, 'foo123');
    }

    it('should validate exp',async function () {
      expect(
        sign({ exp: '1 monkey' })
      ).to.be.rejectedWith(/"exp" should be a number of seconds/);
      await sign({ exp: 10.1 });
    });

  });

});