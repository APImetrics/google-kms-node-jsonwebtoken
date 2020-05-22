'use strict';

const jws = require('jws');
const expect = require('chai').expect;
const path = require('path');
const fs = require('fs');
const testUtils = require('./test-utils')

describe('complete option', async function () {
  const secret = fs.readFileSync(path.join(__dirname, 'priv.pem'));
  const pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));

  const header = { alg: 'RS256' };
  const payload = { iat: Math.floor(Date.now() / 1000 ) };
  const signed = await jws.sign({ header, payload, secret, encoding: 'utf8' });
  const signature = await jws.decode(signed).signature;

  // [
  //   {
  //     description: 'should return header, payload and signature',
  //     complete: true,
  //   },
  // ].forEach((testCase) => {
  //   it(testCase.description, function (done) {
  //     return testUtils.verifyJWTHelper(signed, pub, { typ: 'JWT', complete: testCase.complete }, (err, decoded) => {
  //       return testUtils.asyncCheck(done, () => {
  //         expect(err).to.be.null;
  //         expect(decoded.header).to.have.property('alg', header.alg);
  //         expect(decoded.payload).to.have.property('iat', payload.iat);
  //         expect(decoded).to.have.property('signature', signature);
  //       });
  //     });
  //   });
  // });
  // [
  //   {
  //     description: 'should return payload',
  //     complete: false,
  //   },
  // ].forEach((testCase) => {
  //   it(testCase.description, async function (done) {
  //     await testUtils.verifyJWTHelper(signed, pub, { typ: 'JWT', complete: testCase.complete }, async (err, decoded) => {
  //       await testUtils.asyncCheck(done, () => {
  //         expect(err).to.be.null;
  //         expect(decoded.header).to.be.undefined;
  //         expect(decoded.payload).to.be.undefined;
  //         expect(decoded.signature).to.be.undefined;
  //         expect(decoded).to.have.property('iat', payload.iat);
  //       });
  //     });
  //   });
  // });
});
