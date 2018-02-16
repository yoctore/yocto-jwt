'use strict';

var lockFile  = require('lockfile');
var pem       = require('pem');
var Q         = require('q');
var _         = require('lodash');
var fs        = require('fs');
var path      = require('path');

/**
 * Manage Pem & Cert management
 */
function Pem () {
  // Default pem state without pem generating
  this.state = false;
}

/**
 * Process certificate generation
 *
 * @return {Object} default promise to catch
 */
Pem.prototype.processJwt = function () {
  // Create default async process
  var deferred = Q.defer();

  // Create certificate
  pem.createCertificate({
    days       : 1,
    selfSigned : true
  }, function (error, keys) {
    // Default keys to return
    var bkeys = {};

    // Has error ?
    if (!error) {
      // Create path of the file into cwd()
      var pathFilePK = path.normalize(process.cwd() + '/cert-jwt.tmp');
      var pathLockFile = path.normalize(process.cwd() + '/cert-jwt.lock');

      // Try to create an lockFile, it's usefull for Cluster mode to use the same pem file
      lockFile.lock(pathLockFile, function (error) {
        /**
         * Method to set Pem file into jwt
         *
         * @param {Object} error Optional error if fs method fails
         * @param {value} value Optional data for fs readFile fn
         * @return {Object} result of promise
         */
        var setPemCb = function (error, value) {
          // Check error
          if (error) {
            // An error occured so reject it
            return deferred.reject(error);
          }

          // Check if value exsit
          keys = _.isUndefined(value) ? keys : JSON.parse(value);

          // Merge secure keys
          _.merge(bkeys, keys);

          // Generate public key
          pem.getPublicKey(keys.certificate, function (error, pem) {
            // Has error ?
            if (!error) {
              // Add new item
              _.merge(bkeys, pem);

              // Change state before resolve
              this.state = true;

              // Ok resolve with builded keys
              deferred.resolve(bkeys);
            } else {
              // Reject error occured
              deferred.reject(error);
            }
          }.bind(this));
        }.bind(this);

        // Check if file already exist
        if (error) {
          // File exist so read them
          fs.readFile(pathFilePK, setPemCb);
        } else {
          // File not exist so create them
          fs.writeFile(pathFilePK, JSON.stringify(keys), setPemCb);
        }
      }.bind(this));
    } else {
      // Reject error occured
      deferred.reject(error);
    }
  }.bind(this));

  // Return default promise
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
  // Create default async process
  var deferred = Q.defer();

  // Verify
  pem.getModulus(cert, function (error, certModulus) {
    // Has error ?
    if (error) {
      // Reject an error occured
      deferred.reject(error);
    } else {
      // Get second modulus for matching
      pem.getModulus(key, function (error, keyModulus) {
        // Is valid ?
        if (!error && certModulus.modulus === keyModulus.modulus) {
          // All is ok resolve
          deferred.resolve();
        } else {
          // Reject
          deferred.reject(!error ? 'certificate not match with given key' : error);
        }
      });
    }
  });

  // Return default promise
  return deferred.promise;
};

/**
 * GetCurrent pem state
 *
 * @return {Boolean} true if all is ok false otherwise
 */
Pem.prototype.isReady = function () {
  // Current state
  return this.state;
};

// Default export
module.exports = new Pem();
