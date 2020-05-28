var fs = require('fs');
var path = require('path');
var jwt = require('../index');
var JsonWebTokenError = require('../lib/JsonWebTokenError');
var PS_SUPPORTED = require('../lib/psSupported');
var chai = require('chai');
var expect = chai.expect;
chai.use(require('chai-as-promised'));


var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

describe('when setting a wrong `header.alg`', function () {

  describe('signing with pub key as symmetric', function () {
    it('should not verify', async function () {
      await expect(
        jwt.verify(TOKEN, pub)
      ).to.be.rejectedWith(JsonWebTokenError, /invalid algorithm/);
    });
  });

  describe('signing with pub key as HS256 and whitelisting only RS256', function () {
    it('should not verify', async function () {
      await expect(
        jwt.verify(TOKEN, pub, {algorithms: ['RS256']})
      ).to.be.rejectedWith(JsonWebTokenError, /invalid algorithm/);
    });
  });

  if (PS_SUPPORTED) {
    describe('signing with pub key as HS256 and whitelisting only PS256', function () {
      it('should not verify', async function () {
        await expect(
          jwt.verify(TOKEN, pub, {algorithms: ['PS256']})
        ).to.be.rejectedWith(JsonWebTokenError, /invalid algorithm/);
      });
    });
  }

  describe('signing with HS256 and checking with HS384', function () {
    it('should not verify', async () => {
      await expect((async () => {
        var token = await jwt.sign({foo: 'bar'}, 'secret', {algorithm: 'HS256'})
        await jwt.verify(token, 'some secret', {algorithms: ['HS384']});
      })()).to.be.rejectedWith(JsonWebTokenError, /invalid algorithm/);
    });
  });


});
