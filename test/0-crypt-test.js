var assert = require('chai').assert;
var should = require('chai').should;
var expect = require('chai').expect;
var utils  = require('yocto-utils');

var logger = require('yocto-logger');
var _ = require('lodash');
var c = require('../src')(logger);

logger.enableConsole(false);

// default sate
var data = require('./config.json');
// test part
var key  = '123132136545646';

var signed = {};
 
describe('Algorithm ->', function () {
  _.each(c.algorithms.reverse(), function (algo) {
    it ([ 'Set algorithm value to [', algo, '] must be valid'].join(''), function (done) {
      c.algorithm(algo);
      expect(c.usedAlgorithm).to.be.a.string;
      expect(c.usedAlgorithm).to.be.not.empty;
      expect(c.usedAlgorithm).to.be.equal(algo);
      done();
    });
  });

  it ('At this time load must succeed', function (done) {
    c.load().then(function () {
      expect(true).to.be.a.boolean;
      done();
    });
  });

  it ('Set key must return true', function () {
    var state = c.setKey(key);
    expect(state).to.be.a.boolean;
    expect(state).to.be.equal(true);
  });

  _.each([ '126.32.32.12', [ '126.32.32.12', '126.32.32.25', '126.32.32.30' ],
    [ '10.0.0.0/12', '192.168.1.134' ]], function (i) {
      it ([ 'Setting ip must succeed and contains those value :', i ].join(' '), function (done) {
        c.allowedIps(i);
        expect(c.ips).to.include.members(_.flatten([ i ]));
        done();
      });
  });

  _.each([ { headers : { 'x-forwarded-for' : '10.0.0.10' } },
    { headers : { 'x-forwarded-for' : '126.32.32.12' } } ], function (h) {
    it ([ 'Ip must be allowed for these value :', utils.obj.inspect(h) ].join(' '), function (done) {
      expect(c.ipIsAllowed(h)).to.be.a.boolean;
      expect(c.ipIsAllowed(h)).to.be.equal(true);
      done();
    });
  });

  it ('Generate token must be a string and not empty', function () {
    expect(c.generateAccessToken()).to.be.a.string;
    expect(c.generateAccessToken()).to.be.not.empty;
  });

  it ('Sign must be valid and data can be retreive', function () {
    signed = c.sign(data, { algorithm : c.usedAlgorithm });
    expect(signed).to.be.a.string;
    expect(signed).to.be.not.empty;
    expect(c.decode(signed)).to.be.an.object;
    expect(c.decode(signed)).to.be.not.empty;
  });

  it ('Sign data must be verified', function (done) {
    var verify = c.verify(signed).then(function (dec) {
      expect(dec).to.be.an.object;
      expect(dec).to.be.not.empty;
      done();
    });
  });
});