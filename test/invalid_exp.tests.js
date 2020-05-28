var jwt = require('../index');
var expect = require('chai').expect;

describe('invalid expiration', function() {

  it('should fail with string', async function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjMiLCJmb28iOiJhZGFzIn0.cDa81le-pnwJMcJi3o3PBwB7cTJMiXCkizIhxbXAKRg';

    await jwt.verify(broken_token, '123', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
    });

  });

  it('should fail with 0', async function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsImZvbyI6ImFkYXMifQ.UKxix5T79WwfqAA0fLZr6UrhU-jMES2unwCOFa4grEA';

    await jwt.verify(broken_token, '123', function (err) {
      expect(err.name).to.equal('TokenExpiredError');
    });

  });

  it('should fail with false', async function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOmZhbHNlLCJmb28iOiJhZGFzIn0.iBn33Plwhp-ZFXqppCd8YtED77dwWU0h68QS_nEQL8I';

    await jwt.verify(broken_token, '123', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
    });

  });

  it('should fail with true', async function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnRydWUsImZvbyI6ImFkYXMifQ.eOWfZCTM5CNYHAKSdFzzk2tDkPQmRT17yqllO-ItIMM';

    await jwt.verify(broken_token, '123', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
    });

  });

  it('should fail with object', async function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnt9LCJmb28iOiJhZGFzIn0.1JjCTsWLJ2DF-CfESjLdLfKutUt3Ji9cC7ESlcoBHSY';

    await jwt.verify(broken_token, '123', function (err) {
      expect(err.name).to.equal('JsonWebTokenError');
    });

  });


});