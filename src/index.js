'use strict';

var logger  = require('yocto-logger');
var uuid    = require('uuid');
var fs      = require('fs');
var path    = require('path');
var jwt     = require('jsonwebtoken');
var _       = require('lodash');
var Q       = require('q');
var utils   = require('yocto-utils');

function Jswb (logger) {

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
  this.usedAlgorithm    = 'HS256'

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
 * Retrieve encrypt key
 *
 * @return {String} encrypt key
 */
Jswb.prototype.getKey = function () {
  // default statement
  return this.encryptKey;
};

/**
 * Generate an access token
 *
 * @return {String} encoded access token
 */
Jswb.prototype.generateAccessToken = function (name) {
  // define default name
  name = _.isString(name) && !_.isEmpty(name) ? name : uuid.v4();
  // default statement
  return this.sign({ name : name, date : Date.now() });
};

/**
 * Check if request is authorized
 *
 * @param {Object} context current context to use
 * @return {Function} middleware function to use
 */
Jswb.prototype.isAuthorized = function (context) {
  // default statement
  return function (req, res, next) {
    // testing data
    if (_.isObject(req) && _.isObject(res)) {
      // is json request ?
      if (req.is('application/json')) {
        // debug message
        context.logger.debug('[ Jswb.algorithm ] - checking access on server.');
        // get token
        var token = req.get(context.headers.access);

        // token is undefined ?
        if (_.isUndefined(token)) {
          // send unauthorized
          return res.status(403).send('You d\'ont have access to this ressource.').end();
        } else {
          // process verify
          context.verify(token).then(function (decoded) {
            // next process all is ok
            console.log('decoded => ', decoded);
            return next();
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

// TODO implement base json method
/**
 * Enable auto encryption for json request
 *
 * @param {Object} context current context to use
 * @return {Function} middleware function to use
 */
Jswb.prototype.autoEncryptRequest = function (context) {
  // default statement
  return function (req, res, next) {
    // testing data
    if (_.isObject(req) && _.isObject(res)) {

      // rebuild jsonp
      var _jsonp  = res.jsonp;

      // rewrite jsonp function
      res.jsonp = function (body) {
        // debug message
        context.logger.debug([ '[ Jswb.algorithm ] - Receiving new data to encrypt : ',
                               utils.obj.inspect(body)
                             ].join(' '));
        // set header
        this.header(context.headers.encode, context.getKey());

        // default statement
        return _jsonp.call(this, [ context.sign(body) ]);
      };

    }
    // next statement
    return next();
  };
};

Jswb.prototype.autoDecryptRequest = function (context) {
  // default statement
  return function (req, res, next) {
    // next statement
    return next();
  };
};

/**
 * Set or get algo to use
 *
 * @param {String} value algo to use
 * @return {String} default algo to use
 */
Jswb.prototype.algorithm = function (value) {
  // is defined ?
  if (!_.isUndefined(value) && !_.isNull(value)) {
    // is string and a valid algorithm
    if (_.isString(value) && _.includes(this.algorithms, value)) {
      // set given value
      this.usedAlgorithm = value;
      // message
      this.logger.info([ '[ Jswb.algorithm ] - set algorithm to', value ].join(' '));
    } else {
      // message
      this.logger.warning([ '[ Jswb.algorithm ] - invalid algorithm given. Keep algorithm to',
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
 * @param {Boolean} file, set to true if given key is a file for content reading
 * @return {Boolean} true if all is ok false otherwise
 */
Jswb.prototype.setKey = function (keyOrPath, file) {
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
    this.logger.info('[ Jswb.setKey ] - Setting key done.');
    // valid statement
    return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
  } else {
    // warning message invalid key
    this.logger.warning('[ Jswb.setKey ] - Invalid key or path given.');
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
Jswb.prototype.verify = function (data, remove) {
  // save context
  var context   = this;
  // create async process
  var deferred  = Q.defer();

  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswb.verify ] - Cannot sign your data. Encrypt key is not set');
    // invalid statement
    deferred.reject('[ Jswb.verify ] - Cannot sign your data. Encrypt key is not set');
  }

  // check signature
  jwt.verify(data, this.encryptKey, function (err, decoded) {
    // has error ?
    if (err) {
      // log error
      context.logger.error([ '[ Jswb.verify ] - An error occured :',
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
Jswb.prototype.isReady = function () {
  // default statement
  return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
};

/**
 * Sign data from given key
 *
 * @param {Object} data data to verify
 * @return {String|Boolean} signed data
 */
Jswb.prototype.sign = function (data, options) {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswb.sign ] - Cannot sign your data. Encrypt key is not set');
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
      this.logger.info([ '[ Jswb.sign ] - custom valid algorithm given in options.',
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
 * @param {Object|String}  data given without key
 */
Jswb.prototype.removeJwtKey = function (data) {
  // remove add item ?
  if (_.isObject(data) && !_.isEmpty(data)) {
    var omits = [ 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti' ];

    // omit all items
    _.each(omits, function(o) {
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
 * @return {String} signed data
 */
Jswb.prototype.decode = function (data, remove) {
  // is ready ?
  if (!this.isReady()) {
    // error message
    this.logger.error('[ Jswb.decode ] - Cannot sign your data. Encrypt key is not set');
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
    logger.warning('[ Jswb.constructor ] - Invalid logger given. Use internal logger');
    // assign
    l = logger;
  }

  // default statement
  return new (Jswb)(l);
};