'use strict';

var pem = require('pem');
var Q   = require('q');
var _   = require('lodash');
var fs  = require('fs');
var path = require('path');

/**
 * Manage Pem & Cert management
 */
function Pem () {
  // default pem state without pem generating
  this.state = false;
}

/**
 * Process certificate generation
 *
 * @return {Object} default promise to catch
 */
Pem.prototype.processJwt = function () {
  // create default async process
  var deferred = Q.defer();

  // create certificate
  pem.createCertificate({ days : 1, selfSigned : true }, function (error, keys) {
    // default keys to return
    var bkeys = {};
    // has error ?
    if (!error) {

      // create path of the file into cwd()
      var pathFilePK = path.normalize(process.cwd() + '/cert-jwt.tmp');

      // checck if file already exist to load it
      fs.readFile(pathFilePK, function (err, data) {
        // check if file not exist
        if (err) {
          // file not exsit so should wite the file
          fs.writeFile(pathFilePK, JSON.stringify(keys), function (error) {
            // check if an error occured when creating file
            if (error) {
              deferred.reject(error);
            }
          });
        }

        keys = _.isUndefined(data) ? keys : JSON.parse(data);

        // merge secure keys
        _.merge(bkeys, keys);

        // generate public key
        pem.getPublicKey(keys.certificate, function (error, pem) {
          // has error ?
          if (!error) {
            // add new item
            _.merge(bkeys, pem);

            // change state before resolve
            this.state = true;

            // ok resolve with builded keys
            deferred.resolve(bkeys);
          } else {
            // reject error occured
            deferred.reject(error);
          }
        }.bind(this));
      }.bind(this));
    } else {
      // reject error occured
      deferred.reject(error);
    }
  }.bind(this));

  // return default promise
  return deferred.promise;
};

/**
 * Verify is vertificate is matching with given key
 *
 * @param {String} cert default cert value
 * @param {String} key default key value
 * @return {Object} default promise to catch
 */
Pem.prototype.verify = function (cert, key) {
  // create default async process
  var deferred = Q.defer();

  // verify
  pem.getModulus(cert, function (error, certModulus) {
    // has error ?
    if (error) {
      // reject an error occured
      deferred.reject(error);
    } else {
      // get second modulus for matching
      pem.getModulus(key, function (error, keyModulus) {
        // is valid ?
        if (!error && certModulus.modulus === keyModulus.modulus) {
          // all is ok resolve
          deferred.resolve();
        } else {
          // reject
          deferred.reject((!error ? 'certificate not match with given key' : error));
        }
      });
    }
  });

  // return default promise
  return deferred.promise;
};

/**
 * GetCurrent pem state
 *
 * @return {Boolean} true if all is ok false otherwise
 */
Pem.prototype.isReady = function () {
  // current state
  return this.state;
};

// Default export
module.exports = new (Pem)();
