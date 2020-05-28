var jwt = require('../index');
var PS_SUPPORTED = require('../lib/psSupported');
var fs = require('fs');
var path = require('path');
var ms = require('ms');

var chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;
chai.use(require('chai-as-promised'));

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

var algorithms = {
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  ES256: {
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  }
};

if (PS_SUPPORTED) {
  algorithms.PS256 = {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  };
}


describe('Asymmetric Algorithms', function(){

  Object.keys(algorithms).forEach(function (algorithm) {
    describe(algorithm, function () {
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      // "invalid" means it is not the public key for the loaded "priv" key
      var invalid_pub = algorithms[algorithm].invalid_pub_key;

      describe('when signing a token', async function () {
        var token = await jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should be syntactically valid', async function () {
          expect(token).to.be.a('string');
          expect(token.split('.')).to.have.length(3);
        });

        context('asynchronous', function () {
          it('should validate with public key', async () => {
            await jwt.verify(token, pub, function (err, decoded) {
              assert.ok(decoded.foo);
              assert.equal('bar', decoded.foo);
              // done();
            });
          });

          it('should throw with invalid public key', async () => {
            await jwt.verify(token, invalid_pub, function (err, decoded) {
              assert.isUndefined(decoded);
              assert.isNotNull(err);
              // done();
            });
          });
        });

        context('synchronous', function () {
          it('should validate with public key', async function () {
            var decoded = await jwt.verify(token, pub);
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
          });

          it('should throw with invalid public key', async function () {
            await expect(
              jwt.verify(token, invalid_pub)
            ).to.be.rejectedWith('invalid signature');
          });
        });

      });

      describe('when signing a token with expiration', async function () {
        var token = await jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: '10m' });

        it('should be valid expiration', function () {
          return jwt.verify(token, pub, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            // done();
          });
        });

        it('should be invalid', async function () {
          // expired token
          token = await jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: -1 * ms('10m') });

          await jwt.verify(token, pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'TokenExpiredError');
            assert.instanceOf(err.expiredAt, Date);
            assert.instanceOf(err, jwt.TokenExpiredError);
            // done();
          });
        });

        it('should NOT be invalid', async function () {
          // expired token
          token = await jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: -1 * ms('10m') });

          return jwt.verify(token, pub, { ignoreExpiration: true }, function (err, decoded) {
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
            // done();
          })
        });
      });

      describe('when verifying a malformed token', function () {
        it('should throw fruit', async () => {
          return jwt.verify('fruit.fruit.fruit', pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            // done();
          }).catch((err) => {
            expect(err).to.be.ok;
          });
        });
      });

      describe('when decoding a jwt token with additional parts', async function () {
        var token = await jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should throw foo', async () => {
          return jwt.verify(token + '.foo', pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            // done();
          })
        });
      });

      describe('when decoding a invalid jwt token', function () {
        it('should return null', async () => {
          const payload = await jwt.decode('whatever.token')
          assert.isNull(payload);
        });
      });

      describe('when decoding a valid jwt token', function () {
        it('should return the payload', async () => {
          var obj = { foo: 'bar' };
          var token = await jwt.sign(obj, priv, { algorithm: algorithm });
          var payload = await jwt.decode(token);
          assert.equal(payload.foo, obj.foo);
        });
        it(
          'should return the header and payload and signature if complete option is set', 
          async () =>{
            var obj = { foo: 'bar' };
            var token = await jwt.sign(obj, priv, { algorithm: algorithm });
            var decoded = await jwt.decode(token, { complete: true });
            assert.equal(decoded.payload.foo, obj.foo);
            assert.deepEqual(decoded.header, { typ: 'JWT', alg: algorithm });
            assert.ok(typeof decoded.signature == 'string');
          }
        );
      });
    });
  });
});
