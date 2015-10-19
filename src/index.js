'use strict';

var logger  = require('yocto-logger');
var uuid    = require('uuid');
var fs      = require('fs');
var path    = require('path');
var jwt     = require('jsonwebtoken');
var _       = require('lodash');
var Q       = require('q');
var utils   = require('yocto-utils');
var crypto  = require('crypto');
var pem     = require('./modules/pem');

/**
 * Manage jwt token and encryption
 */
function Jswt (logger) {

  /**
   * Default logger instance
   *
   * @property logger
   * @type Object
   */
  this.logger           = logger;

  /**
   * Default encrypt key
   *
   * @property encryptKey
   * @type {String}
   */
  this.encryptKey       = '';

  /**
   * Default secure key for authorized process
   *
   * @property secureKeys
   * @type {Object}
   */
  this.secureKeys = {
    // web shared key
    publicKey     : '',
    // private key
    clientKey     : '',
    // certificate value
    certificate   : '',
    // service key value
    serviceKey    : '',
    // csr
    csr           : ''
  };

  /**
   * Default algorithms list
   *
   * @property algorithms
   * @type {Array}
   */
  this.algorithms       = [ 'HS256', 'HS384', 'HS512', 'RS256',
                            'RS384', 'RS512', 'ES256', 'ES384',
                            'ES512' ];

  /**
   * Default algorithm to used
   *
   * @property usedAlgorithm
   * @type {String}
   * @default HS256
   */
  this.usedAlgorithm    = 'HS256';

  /**
   * Default auth header for express usage
   *
   * @property authHeader
   * @type {String}
   * @default X-ACCESS-TOKEN
   */
  this.headers          = {
    access : 'x-jwt-access-token',
    encode : 'x-jwt-decode-token'
  };
}

/**
 * Process cert generation
 *
 * @return {Object} promise to catc
 */
Jswt.prototype.load = function () {
  // create async process
  var deferred  = Q.defer();
  // save current context
  var context   = this;

  // load ptem date
  pem.processJwt().then(function (success) {
    // merge data
    _.merge(context.secureKeys, success);
    // resolve all is okay
    deferred.resolve();
  }).catch(function (error) {
    deferred.reject(error);
  });

  // process certificate process
  return deferred.promise;
};

/**
 * Retrieve encrypt key
 *
 * @return {String} encrypt key
 */
Jswt.prototype.getKey = function () {
  // default statement
  return this.encryptKey;
};

/**
 * Retrieve private key
 *
 * @return {String} private key
 */
Jswt.prototype.getPrivateKey = function () {
  // default statement
  return this.secureKeys.clientKey;
};

/**
 * Retrieve public key
 *
 * @return {String} public key
 */
Jswt.prototype.getPublicKey = function () {
  // default statement
  return this.secureKeys.publicKey;
};

/**
 * Retrieve access encrypt key
 *
 * @return {String|Boolean} encrypt key
 */
Jswt.prototype.getAccessKey = function () {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error([ '[ Jswt.getAccessKey ] -',
                        'Cannot get access key. Encrypt key is not set' ].join(' '));
    // invalid statement
    return false;
  }

  // private key is set ?
  if (!pem.isReady()) {
    // error message
    this.logger.error([ '[ Jswt.getAccessKey ] -',
                        'Cannot get access key. Certificate was not genrated.' ].join(' '));
    // invalid statement
    return false;
  }

  // create hash
  var hash = crypto.createHash('sha1').update(this.getPublicKey()).digest('hex');

  // default statement with key generation
  return utils.crypto.encrypt(hash, this.getPublicKey());
};

/**
 * Generate an access token
 *
 * @param {String} name name to use in token generation
 * @return {String|Boolean} encoded access token
 */
Jswt.prototype.generateAccessToken = function (name) {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error([ '[ Jswt.generateAccessToken ] -',
                        'Cannot generate access token. Encrypt key is not set' ].join(' '));
    // invalid statement
    return false;
  }

  // private key is set ?
  if (!pem.isReady()) {
    // error message
    this.logger.error([ '[ Jswt.generateAccessToken ] -',
                        'Cannot generate access token. Certificate was not genrated.' ].join(' '));
    // invalid statement
    return false;
  }

  // save access key for next process
  var aKey    = this.getAccessKey();
  // define default name
  name        = _.isString(name) && !_.isEmpty(name) ? name : uuid.v4();
  // define expires value
  var expires = name === aKey ? '1h' : '5m';

  // default statement
  return this.sign({
    name  : name,
    date  : Date.now(),
    key   : aKey
  }, { expiresIn : expires });
};

/**
 * Check if request is authorized
 *
 * @param {Object} context current context to use
 * @return {Function} middleware function to use
 */
Jswt.prototype.isAuthorized = function (context) {
  // default statement
  return function (req, res, next) {
    // testing data
    if (_.isObject(req) && _.isObject(res)) {
      // is json request ?
      if (req.is('application/json')) {
        // debug message
        context.logger.debug('[ Jswt.isAuthorized ] - checking access on server.');
        // get token
        var token = req.get(context.headers.access.toLowerCase());

        // token is undefined ?
        if (_.isUndefined(token)) {
          // send unauthorized
          return res.status(403).send('You d\'ont have access to this ressource.').end();
        } else {
          // process verify
          context.verify(token).then(function (decoded) {
            // all is ok so check key content
            var akey  = crypto.createHash('sha1').update(context.getPublicKey()).digest('hex');
            var bkey  = utils.crypto.decrypt(akey, decoded.key.toString());

            // is valid bkey
            if (bkey !== false) {
              // verify
              pem.verify(context.secureKeys.certificate,
                         context.secureKeys.clientKey).then(function () {
                // debug message
                context.logger.debug('[ Jswt.isAuthorized ] - given token seems to be valid');
                // all is ok so next process
                return next();
              }).catch(function (error) {
                // log warning message
                context.logger.error([ '[ Jswt.isAuthorized ] - ', error ].join(' '));
                // invalid key
                return res.status(403).send('Invalid Token.');
              });
            } else {
              // invalid key
              return res.status(403).send('Invalid Token.');
            }
          }).catch(function (error) {
            // is expired ?
            if (_.has(error, 'expiredAt')) {
              // refresh token error
              return res.status(403).send('Token has expired.');
            }

            // send unauthorized
            return res.status(403).send([ 'Cannot validate your access.',
                                          'Please retry.' ].join(' ')).end();
          });
        }
      } else {
        // next statement
        return next();
      }
    } else {
      // next statement
      return next();
    }
  };
};

/**
 * Enable auto encryption for json request
 *
 * @param {Object} context current context to use
 * @return {Function} middleware function to use
 */
Jswt.prototype.autoEncryptRequest = function (context) {
  // default statement
  return function (req, res, next) {
    // testing data
    if (_.isObject(req) && _.isObject(res)) {

      // witch method we need to overide
      var mtds  = [ 'json', 'jsonp' ];

      // parse methods to process
      _.each(mtds, function (m) {
        // rebuild jsonp
        var mcall  = res[m];

        // rewrite jsonp function
        res[m] = function (body) {
          // debug message
          context.logger.debug([ '[ Jswt.autoEncryptRequest ] - Receiving new data to encrypt : ',
                                 utils.obj.inspect(body)
                               ].join(' '));
          // default statement
          return mcall.call(this, [ context.sign(body) ]);
        };
      }, context);
    }
    // next statement
    return next();
  };
};

/**
 * Auto decryption method. Decrypt json request
 *
 * @param {Object} context current context to use
 * @return {Function} middleware function to use
 */
Jswt.prototype.autoDecryptRequest = function (context) {
  // default statement
  return function (req, res, next) {
    // is json
    if (req.is('application/json')) {
      // debug message
      context.logger.debug([ '[ Jswt.autoDecryptRequest ] - Receiving new data to decrypt : ',
                             utils.obj.inspect(req.body)
                           ].join(' '));
      // default body value
      var body = req.body;
      // process body data to correct format
      if (_.isObject(req.body) && !_.isEmpty(req.body)) {
        body = _.first(req.body);
      }

      // process verify
      context.verify(body).then(function (decoded) {
        // remove non needed key
        req.body = context.removeJwtKey(decoded);
        // next statement
        next();
      }).catch(function (error) {
        // log message
        context.logger.error([ '[ Jswt.autoDecryptRequest ] -', error ].join(' '));
        // next statement
        next();
      });
    } else {
      // next statement
      return next();
    }
  };
};

/**
 * Set or get algo to use
 *
 * @param {String} value algo to use
 * @return {String} default algo to use
 */
Jswt.prototype.algorithm = function (value) {
  // is defined ?
  if (!_.isUndefined(value) && !_.isNull(value)) {
    // is string and a valid algorithm
    if (_.isString(value) && _.includes(this.algorithms, value)) {
      // set given value
      this.usedAlgorithm = value;
      // message
      this.logger.info([ '[ Jswt.algorithm ] - set algorithm to', value ].join(' '));
    } else {
      // message
      this.logger.warning([ '[ Jswt.algorithm ] - invalid algorithm given. Keep algorithm to',
                            this.usedAlgorithm
                          ].join(' '));
    }
  }

  // default statement
  return this.usedAlgorithm;
};

/**
 * Default function to set encryption key
 *
 * @param {String} keyOrPath key or path to use for encryption
 * @param {Boolean} file set to true if given key is a file for content reading
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.setKey = function (keyOrPath, file) {
  // set default for is file check
  file = _.isBoolean(file) ? file : false;

  // is string ?
  if (_.isString(keyOrPath) && !_.isEmpty(keyOrPath)) {
    // is file
    if (file) {
      // is relative ?
      if (!path.isAbsolute(keyOrPath)) {
        // normalize path
        keyOrPath = path.normalize([ process.cwd(), keyOrPath ].join('/'));
      }
      // process file process
      keyOrPath = fs.readFileSync(keyOrPath);
    }

    // set value
    this.encryptKey = keyOrPath;
    // message
    this.logger.info('[ Jswt.setKey ] - Setting key done.');
    // valid statement
    return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
  } else {
    // warning message invalid key
    this.logger.warning('[ Jswt.setKey ] - Invalid key or path given.');
  }

  // invalid statement
  return false;
};

/**
 * Set private key for internal encryption
 *
 * @param {String} value key to use for private key
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.setPrivateKey = function (value) {
  // is a string ?
  if (!_.isString(value) && !_.isEmpty(value)) {
    // set key
    this.privateKey = value;
    // valid statement
    return true;
  }

  // invalid statement
  return false;
};

/**
 * Check signature of given object
 *
 * @param {Object} data data to verify
 * @param {Boolean} remove true if we need to remove added jwt key, false otherwise
 * @return {Object} default promise
 */
Jswt.prototype.verify = function (data, remove) {
  // save context
  var context   = this;
  // create async process
  var deferred  = Q.defer();

  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set');
    // invalid statement
    deferred.reject('[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set');
  }

  // check signature
  jwt.verify(data, this.encryptKey, function (err, decoded) {
    // has error ?
    if (err) {
      // log error
      context.logger.error([ '[ Jswt.verify ] - An error occured :',
                              err.message, err.expiredAt || '' ].join(' '));
      // reject verify is invalid
      deferred.reject(err);
    } else {
      // remove add item ?
      if (_.isBoolean(remove) && remove) {
        // decoded data
        decoded = context.removeJwtKey(decoded);
      }
      // ok so resolve
      deferred.resolve(decoded);
    }
  });

  // default promise
  return deferred.promise;
};

/**
 * Test if is app is ready or not
 *
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.isReady = function () {
  // default statement
  return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
};

/**
 * Sign data from given key
 *
 * @param {Object} data data to verify
 * @return {String|Boolean} signed data
 */
Jswt.prototype.sign = function (data, options) {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswt.sign ] - Cannot sign your data. Encrypt key is not set');
    // invalid statement
    return false;
  }

  // default options object
  options  = options || {};
  // has algo rules defined ?
  if (_.has(options, 'algorithm')) {
    // merge algo
    if (!_.includes(this.algorithms, options.algorithm)) {
      // merge with current algo
      _.merge(options, { algorithm : this.algorithm() });
    } else {
      // message
      this.logger.info([ '[ Jswt.sign ] - custom valid algorithm given in options.',
                         'Use', options.algorithm, 'for encryption' ].join(' '));
    }
  }

  // return sign data
  return jwt.sign(data, this.encryptKey, options);
};

/**
 * Utility function to remove added jwt key on data
 *
 * @param {Object|String} data object to process
 * @return {Object|String} data given without key
 */
Jswt.prototype.removeJwtKey = function (data) {
  // remove add item ?
  if (_.isObject(data) && !_.isEmpty(data)) {
    var omits = [ 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti' ];

    // omit all items
    _.each(omits, function (o) {
      data = _.omit(data, o);
    });
  }

  // default statement
  return data;
};

/**
 * Decode data without signature verification
 *
 * @param {Object} data data to verify
 * @param {Boolean} remove true if we need to remove added jwt key, false otherwise
 * @return {String|Boolean} signed data
 */
Jswt.prototype.decode = function (data, remove) {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswt.decode ] - Cannot sign your data. Encrypt key is not set');
    // invalid statement
    return false;
  }

  // return sign data
  var decoded = jwt.decode(data);

  // remove add item ?
  if (_.isBoolean(remove) && remove) {
    // decoded data
    decoded = this.removeJwtKey(decoded);
  }

  // default statement
  return decoded;
};

// Default export
module.exports = function (l) {
  // is a valid logger ?
  if (_.isUndefined(l) || _.isNull(l)) {
    logger.warning('[ Jswt.constructor ] - Invalid logger given. Use internal logger');
    // assign
    l = logger;
  }

  // default statement
  return new (Jswt)(l);
};
