var jwt = require('../index');
var expect = require('chai').expect;
var jws = require('jws');
var PS_SUPPORTED = require('../lib/psSupported');

describe('signing a token asynchronously', function() {

  describe('when signing a token', function() {
    var secret = 'shhhhhh';

    it('should return the same result as singing synchronously', async () => {
      await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' }, async (err, asyncToken) => {
        // if (err) return done(err);
        expect(err).to.be.null;
        var syncToken = await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
        expect(asyncToken).to.be.a('string');
        expect(asyncToken.split('.')).to.have.length(3);
        expect(asyncToken).to.equal(syncToken);
        // done();
      });
    });

    it('should work with empty options', async () => {
      await jwt.sign({abc: 1}, "secret", {}, (err) => {
        expect(err).to.be.null;
      });
    });

    it('should work without options object at all', async () => {
      await jwt.sign({abc: 1}, "secret", async (err) => {
        expect(err).to.be.null;
      });
    });

    it('should work with none algorithm where secret is set', async () => {
      await jwt.sign({ foo: 'bar' }, 'secret', { algorithm: 'none' }, (err, token) => {
        expect(token).to.be.a('string');
        expect(token.split('.')).to.have.length(3);
      });
    });

    //Known bug: https://github.com/brianloveswords/node-jws/issues/62
    //If you need this use case, you need to go for the non-callback-ish code style.
    it.skip('should work with none algorithm where secret is falsy', async () => {
      await jwt.sign({ foo: 'bar' }, undefined, { algorithm: 'none' }, (err, token) => {
        expect(token).to.be.a('string');
        expect(token.split('.')).to.have.length(3);
      })
    });

    it('should return error when secret is not a cert for RS256', async () => {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'RS256' }, (err) => {
        expect(err).to.be.ok;
      }).catch((err) => {
        expect(err).to.be.ok;
      });
    });

    if (PS_SUPPORTED) {
      it('should return error when secret is not a cert for PS256', async () => {
        //this throw an error because the secret is not a cert and PS256 requires a cert.
        await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'PS256' }, (err) => {
          expect(err).to.be.ok;
        }).catch((err) => {
          expect(err).to.be.ok;
        });
      });
    }

    it('should return error on wrong arguments', async () => {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      await jwt.sign({ foo: 'bar' }, secret, { notBefore: {} }, (err) => {
        expect(err).to.be.ok;
      }).catch((err) => {
        expect(err).to.be.ok;
      });
    });

    it('should return error on wrong arguments (2)', async () => {
      await jwt.sign('string', 'secret', {noTimestamp: true}, (err) => {
        expect(err).to.be.ok;
        expect(err).to.be.instanceof(Error);
      }).catch((err) => {
        expect(err).to.be.ok;
      });
    });

    it('should not stringify the payload', async () => {
      await jwt.sign('string', 'secret', {}, (err, token) => {
        expect(err).to.be.null;
        expect(jws.decode(token).payload).to.equal('string');
      });
    });

    describe('when mutatePayload is not set', function() {
      it('should not apply claims to the original payload object (mutatePayload defaults to false)', async () => {
        var originalPayload = { foo: 'bar' };
        await jwt.sign(originalPayload, 'secret', { notBefore: 60, expiresIn: 600 }, (err) => {
          expect(err).to.be.null;
          expect(originalPayload).to.not.have.property('nbf');
          expect(originalPayload).to.not.have.property('exp');
        });
      });
    });

    describe('when mutatePayload is set to true', function() {
      it('should apply claims directly to the original payload object', async () => {
        var originalPayload = { foo: 'bar' };
        await jwt.sign(originalPayload, 'secret', { notBefore: 60, expiresIn: 600, mutatePayload: true }, (err) => {
          expect(err).to.be.null;
          expect(originalPayload).to.have.property('nbf').that.is.a('number');
          expect(originalPayload).to.have.property('exp').that.is.a('number');
        });
      });
    });

    describe('secret must have a value', function(){
      [undefined, '', 0].forEach((secret) => {
        it(
          'should return an error if the secret is falsy and algorithm is not set to none: ' + (typeof secret === 'string' ? '(empty string)' : secret), 
          async () => {
            // This is needed since jws will not answer for falsy secrets
            await jwt.sign('string', secret, {}, function(err, token) {
              expect(err).to.exist;
              expect(err.message).to.equal('secretOrPrivateKey must have a value');
              expect(token).to.not.exist;
            });
          });
      });
    });
  });
});
