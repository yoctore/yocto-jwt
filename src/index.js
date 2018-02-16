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
var Netmask = require('netmask').Netmask;

/**
 * Manage jwt token and encryption
 *
 * @param {Object} logger Logger instance
 */
function Jswt (logger) {
  /**
   * Default logger instance
   *
   * @property logger
   * @type Object
   */
  this.logger = logger;

  /**
   * Default encrypt key
   *
   * @property encryptKey
   * @type {String}
   */
  this.encryptKey = '';

  /**
   * Default secure key for authorized process
   *
   * @property secureKeys
   * @type {Object}
   */
  this.secureKeys = {
    // Web shared key
    publicKey : '',

    // Private key
    clientKey : '',

    // Certificate value
    certificate : '',

    // Service key value
    serviceKey : '',

    // Csr
    csr : ''
  };

  /**
   * Default algorithms list
   *
   * @property algorithms
   * @type {Array}
   */
  this.algorithms = [ 'HS256', 'HS384', 'HS512', 'RS256',
    'RS384', 'RS512', 'ES256', 'ES384',
    'ES512' ];

  /**
   * Default algorithm to used
   *
   * @property usedAlgorithm
   * @type {String}
   * @default HS256
   */
  this.usedAlgorithm = 'HS256';

  /**
   * Default auth header for express usage
   *
   * @property authHeader
   * @type {String}
   * @default X-ACCESS-TOKEN
   */
  this.headers = {
    access : 'x-jwt-access-token',
    encode : 'x-jwt-decode-token'
  };

  /**
   * Default alowed ip storage
   *
   * @property ips
   * @type {Array}
   * @default [ '::1', '127.0.0.1' ]
   */
  this.ips = [ '1', '::1', '127.0.0.1' ];

  /**
   * Array of routes to allowed without jwt validation
   * All item should be regexp
   *
   * @type {Array}
   */
  this.allowedRoutes = [];
}

/**
 * Process cert generation
 *
 * @return {Object} promise to catc
 */
Jswt.prototype.load = function () {
  // Create async process
  var deferred  = Q.defer();

  // Load ptem date

  pem.processJwt().then(function (success) {
    // Merge data
    _.merge(this.secureKeys, success);

    // Resolve all is okay
    deferred.resolve();
  }.bind(this)).catch(function (error) {
    deferred.reject(error);
  });

  // Process certificate process
  return deferred.promise;
};

/**
 * Retrieve encrypt key
 *
 * @return {String} encrypt key
 */
Jswt.prototype.getKey = function () {
  // Default statement
  return this.encryptKey;
};

/**
 * Retrieve private key
 *
 * @return {String} private key
 */
Jswt.prototype.getPrivateKey = function () {
  // Default statement
  return this.secureKeys.clientKey;
};

/**
 * Retrieve public key
 *
 * @return {String} public key
 */
Jswt.prototype.getPublicKey = function () {
  // Default statement
  return this.secureKeys.publicKey;
};

/**
 * Retrieve access encrypt key
 *
 * @return {String|Boolean} encrypt key
 */
Jswt.prototype.getAccessKey = function () {
  // Is ready ?
  if (!this.isReady()) {
    // Error message
    this.logger.error([ '[ Jswt.getAccessKey ] -',
      'Cannot get access key. Encrypt key is not set' ].join(' '));

    // Invalid statement
    return false;
  }

  // Private key is set ?
  if (!pem.isReady()) {
    // Error message
    this.logger.error([ '[ Jswt.getAccessKey ] -',
      'Cannot get access key. Certificate was not genrated.' ].join(' '));

    // Invalid statement
    return false;
  }

  // Create hash
  var hash = crypto.createHash('sha1').update(this.getPublicKey()).digest('hex');

  // Default statement with key generation
  return utils.crypto.encrypt(hash, this.getPublicKey());
};

/**
 * Generate an access token
 *
 * @param {String} name name to use in token generation
 * @return {String|Boolean} encoded access token
 */
Jswt.prototype.generateAccessToken = function (name) {
  // Is ready ?
  if (!this.isReady()) {
    // Error message
    this.logger.error([ '[ Jswt.generateAccessToken ] -',
      'Cannot generate access token. Encrypt key is not set' ].join(' '));

    // Invalid statement
    return false;
  }

  // Private key is set ?
  if (!pem.isReady()) {
    // Error message
    this.logger.error([ '[ Jswt.generateAccessToken ] -',
      'Cannot generate access token. Certificate was not genrated.' ].join(' '));

    // Invalid statement
    return false;
  }

  // Save access key for next process
  var aKey    = this.getAccessKey();

  // Define default name

  name = _.isString(name) && !_.isEmpty(name) ? name : uuid.v4();

  // Define expires value
  var expires = name === aKey ? '1h' : '5m';

  // Default statement
  return this.sign({
    name : name,
    date : Date.now(),
    key  : aKey
  }, {
    expiresIn : expires
  });
};

/**
 * An utility method to add allowed ips on jwt
 *
 * @param {Array|String} ips array of ips or single ip to add
 */
Jswt.prototype.allowedIps = function (ips) {
  // Normalize ips add action
  this.ips = _.uniq(_.flatten([ this.ips, _.isArray(ips) ? ips : [ ips ] ]));
};

/**
 * An utility method to add allowed routes that will be ignored to jwt check
 *
 * @param {Array|String} allowedRoutes array of regexp route to allow
 */
Jswt.prototype.addAllowedRoutes = function (allowedRoutes) {
  // Normalize allowedRoutes add action
  this.allowedRoutes = _.uniq(_.flatten([ this.allowedRoutes, _.isArray(allowedRoutes) ?
    allowedRoutes : [ allowedRoutes ] ]));
};

/**
 * Default method to check if the route of current request is allowed
 *
 * @param {Object} url url to check
 * @return {Boolean} true if is allowed false otherwise
 */
Jswt.prototype.isAllowedRoutes = function (url) {
  // Var used to determine if the route was allowed
  var allowed = false;

  // Parse all allowed routes
  _.every(this.allowedRoutes, function (route) {
    try {
      // Retrieve the regexp
      route = _.isRegExp(route) ? route : new RegExp(route);

      // Check if regexp match
      if (route.test(url)) {
        // Set true because the route match
        allowed = true;

        // Log incomming error
        this.logger.debug('[ Jswt.isAllowedRoutes ] - the url ' + url +
        ' was authorized to connect without jwt validation with patern : ' + route);

        // Return false to break the _.every
        return false;
      }
    } catch (e) {
      // Return false because not match or regexp constructor failed
      return false;
    }

    // Return true to continue the _.every
    return true;
  }.bind(this));

  // Default statement
  return allowed;
};

/**
 * Default method to check if current request ip is allowed
 *
 * @param {String} ip current ip form req
 * @return {Boolean} true if is allowed false otherwise
 */
Jswt.prototype.ipIsAllowed = function (ip) {
  // Remove unecessarry data
  ip = _.trimStart(ip, '::ffff:');

  // Current regexp ip
  var submask = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})$/;

  // Default found state
  var allowed = false;

  // Parse all ip and build ip if is submask
  _.every(this.ips, function (ips) {
    // Allow all
    allowed = ips === '*';

    // Is submask
    if (!allowed && submask.test(ips)) {
      // Try catch process ?
      try {
        var netmask = new Netmask(ips);

        // Continue

        allowed = netmask.contains(ip);
      } catch (e) {
        // Log error
        this.logger.error([ '[ Jswt.ipIsAllowed ] - ', ip, 'Netmask error :',
          e ].join(' '));
      }
    } else {
      // If not a submask so check directly if ip is on list or if is wilcard
      allowed = _.includes(this.ips, ip) || ips === '*';
    }

    // Stop when found
    return !allowed;
  }.bind(this));

  // Default statement
  return allowed;
};

/**
 * Check if request is authorized
 *
 * @return {Function} middleware function to use
 */
Jswt.prototype.isAuthorized = function () {
  // Default statement
  return function (req, res, next) {
    // Testing data
    if (_.isObject(req) && _.isObject(res)) {
      // Get current ip
      var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

      // Log incomming request
      this.logger.debug('[ Jswt.isAuthorized ] - a new request incoming into url : ' + req.url +
      ' - from IP : ' + ip);

      // Save result of is allowed routes
      var isAllowedRoutes = this.isAllowedRoutes(req.url);

      // Ip is allowed or route is allowed ?
      if (isAllowedRoutes || this.ipIsAllowed(ip)) {
        // Get token in headers
        var token = req.get(this.headers.access.toLowerCase());

        // Token is undefined ?
        if (!_.isUndefined(token)) {
          // Process verify
          this.verify(token).then(function (decoded) {
            // Is not an json request ?
            if (!req.is('application/json')) {
              // Debug message
              this.logger.debug('[ Jswt.isAuthorized ] - valid token, but not application/json');

              // Next statement
              return next();
            }

            // All is ok so check key content
            var akey  = crypto.createHash('sha1').update(this.getPublicKey()).digest('hex');
            var bkey  = utils.crypto.decrypt(akey, decoded.key.toString());

            // Is valid bkey
            if (bkey !== false) {
              // Verify
              pem.verify(this.secureKeys.certificate,
                this.secureKeys.clientKey).then(function () {
                // Debug message
                this.logger.debug('[ Jswt.isAuthorized ] - given token seems to be valid');

                // All is ok so next process
                return next();
              }.bind(this)).catch(function (error) {
                // Log warning message
                this.logger.error([ '[ Jswt.isAuthorized ] - ', error ].join(' '));

                // Invalid key
                return res.status(403).send('Invalid Token AAAA.');
              }.bind(this));
            } else {
              // Invalid key
              return res.status(403).send('Invalid Token BBB.');
            }
          }.bind(this)).catch(function (error) {
            // Is expired ?
            if (_.has(error, 'expiredAt')) {
              // Refresh token error
              return res.status(403).send('Token has expired.');
            }

            // Send unauthorized
            return res.status(403).send([ 'Cannot validate your access.',
              'Please retry.' ].join(' ')).end();
          });
        } else if (isAllowedRoutes) {
          // Is an allowed routes so next statement
          return next();
        } else {
          // Log incomming error
          this.logger.error('[ Jswt.isAuthorized ] - request to url : ' + req.url +
          ' for IP : ' + ip + ' try to access route but is not an allowed routes and is not and' +
          ' have no request token');

          // Send unauthorized
          return res.status(403).send('You are not allowed to access to this ressource.').end();
        }
      } else {
        // Log incomming error
        this.logger.error('[ Jswt.isAuthorized ] - request to url : ' + req.url +
        ' is NOT allowed for IP : ' + ip);

        // Send unauthorized
        return res.status(403).send('You are not allowed to access to this ressource.').end();
      }
    } else {
      // Next statement
      return next();
    }
  }.bind(this);
};

/**
 * Enable auto encryption for json request
 *
 * @return {Function} middleware function to use
 */
Jswt.prototype.autoEncryptRequest = function () {
  // Default statement
  return function (req, res, next) {
    // Testing data
    if (_.isObject(req) && _.isObject(res)) {
      // Witch method we need to overide
      var mtds  = [ 'json', 'jsonp' ];

      // Parse methods to process
      _.forEach(mtds, function (m) {
        // Rebuild jsonp
        var mcall  = res[m];

        // Save current context here to keep safe response context
        var context = this;

        // Rewrite jsonp function

        res[m] = function (body) {
          // Debug message
          context.logger.debug([ '[ Jswt.autoEncryptRequest ] - Receiving new data to encrypt : ',
            utils.obj.inspect(body)
          ].join(' '));

          // Default statement
          return mcall.call(this, [ context.sign(body) ]);
        };
      }.bind(this));
    }

    // Next statement
    return next();
  }.bind(this);
};

/**
 * Auto decryption method. Decrypt json request
 *
 * @return {Function} middleware function to use
 */
Jswt.prototype.autoDecryptRequest = function () {
  // Default statement
  return function (req, res, next) {
    // Is json
    if (req.is('application/json')) {
      // Continue
      // debug message
      this.logger.debug([ '[ Jswt.autoDecryptRequest ] - Receiving new data to decrypt : ',
        utils.obj.inspect(req.body)
      ].join(' '));

      // Default body value
      var body = req.body;

      if (!_.isEmpty(body)) {
        // Process body data to correct format
        if (req.body.length === 1 && _.first(req.body) && !_.isEmpty(_.first(req.body))) {
          body = _.first(req.body);
        }

        // Process verify
        this.verify(body).then(function (decoded) {
          // Remove non needed key
          req.body = this.removeJwtKey(decoded);

          // Next statement
          next();
        }.bind(this)).catch(function (error) {
          // Log message
          this.logger.error([ '[ Jswt.autoDecryptRequest ] -', error ].join(' '));

          // Send an error to client because data was not signed
          return res.status(403).send('You d\'ont have access to this ressource.').end();
        }.bind(this));
      } else {
        // Next process
        return next();
      }
    } else {
      // Next statement
      return next();
    }
  }.bind(this);
};

/**
 * Set or get algo to use
 *
 * @param {String} value algo to use
 * @return {String} default algo to use
 */
Jswt.prototype.algorithm = function (value) {
  // Is defined ?
  if (!_.isUndefined(value) && !_.isNull(value)) {
    // Is string and a valid algorithm
    if (_.isString(value) && _.includes(this.algorithms, value)) {
      // Set given value
      this.usedAlgorithm = value;

      // Message
      this.logger.info([ '[ Jswt.algorithm ] - set algorithm to', value ].join(' '));
    } else {
      // Message
      this.logger.warning([ '[ Jswt.algorithm ] - invalid algorithm given. Keep algorithm to',
        this.usedAlgorithm
      ].join(' '));
    }
  }

  // Default statement
  return this.usedAlgorithm;
};

/**
 * Default function to set encryption key
 *
 * @param {String} keyOrPath key or path to use for encryption
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.setKey = function (keyOrPath) {
  // Set default for is file value
  var isFile = false;

  // Is string ?
  if (_.isString(keyOrPath) && !_.isEmpty(keyOrPath)) {
    // Is file
    var savedKeyOrPath = keyOrPath;

    // Is relative ?
    if (!path.isAbsolute(keyOrPath)) {
      // Normalize path
      keyOrPath = path.normalize([ process.cwd(), keyOrPath ].join('/'));
    }

    // Try here exception can be throwed
    try {
      // Parse file
      var parse   = fs.statSync(keyOrPath);

      // Change state

      isFile = parse.isFile();
    } catch (e) {
      // Warn message
      this.logger.warning('[ Jswt.setKey ] - key is not a file. Process key like a string.');
    }

    // Is file ?
    if (isFile) {
      // Process file process
      keyOrPath = fs.readFileSync(keyOrPath);
    }

    // Set value
    this.encryptKey = isFile ? keyOrPath : savedKeyOrPath;

    // Message
    this.logger.info('[ Jswt.setKey ] - Setting key done.');

    // Valid statement
    return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
  }

  // Warning message invalid key
  this.logger.warning('[ Jswt.setKey ] - Invalid key or path given.');


  // Invalid statement
  return false;
};

/**
 * Set private key for internal encryption
 *
 * @param {String} value key to use for private key
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.setPrivateKey = function (value) {
  // Is a string ?
  if (!_.isString(value) && !_.isEmpty(value)) {
    // Set key
    this.privateKey = value;

    // Valid statement
    return true;
  }

  // Invalid statement
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
  // Create async process
  var deferred  = Q.defer();

  // Is ready ?
  if (!this.isReady()) {
    // Error message
    this.logger.error('[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set');

    // Invalid statement
    deferred.reject('[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set');
  }

  try {
    // Check signature
    jwt.verify(data, this.encryptKey, function (err, decoded) {
      // Has error ?
      if (err) {
        // Log error
        this.logger.error([ '[ Jswt.verify ] - An error occured :',
          err.message, err.expiredAt || '' ].join(' '));

        // Reject verify is invalid
        deferred.reject(err);
      } else {
        // Remove add item ?
        if (_.isBoolean(remove) && remove) {
          // Decoded data
          decoded = this.removeJwtKey(decoded);
        }

        // Ok so resolve
        deferred.resolve(decoded);
      }
    }.bind(this));
  } catch (error) {
    // Error message
    this.logger.error([ '[ Jswt.verify ] - Cannot cerify your data :', error ].join(' '));

    // Reject
    deferred.reject('Cannot certify your data.');
  }

  // Default promise
  return deferred.promise;
};

/**
 * Test if is app is ready or not
 *
 * @return {Boolean} true if all is ok false otherwise
 */
Jswt.prototype.isReady = function () {
  // Default statement
  return _.isString(this.encryptKey) && !_.isEmpty(this.encryptKey);
};

/**
 * Sign data from given key
 *
 * @param {Object} data data to verify
 * @param {Object} options option to sign
 * @return {String|Boolean} signed data
 */
Jswt.prototype.sign = function (data, options) {
  // Is ready ?
  if (!this.isReady()) {
    // Error message
    this.logger.error('[ Jswt.sign ] - Cannot sign your data. Encrypt key is not set');

    // Invalid statement
    return false;
  }

  // Default options object
  options = options || {};

  // Has algo rules defined ?
  if (_.has(options, 'algorithm')) {
    // Merge algo
    if (!_.includes(this.algorithms, options.algorithm)) {
      // Merge with current algo
      _.merge(options, {
        algorithm : this.algorithm()
      });
    } else {
      // Message
      this.logger.info([ '[ Jswt.sign ] - custom valid algorithm given in options.',
        'Use', options.algorithm, 'for encryption' ].join(' '));
    }
  }

  // Return sign data
  return jwt.sign(data, this.encryptKey, options);
};

/**
 * Utility function to remove added jwt key on data
 *
 * @param {Object|String} data object to process
 * @return {Object|String} data given without key
 */
Jswt.prototype.removeJwtKey = function (data) {
  // Remove add item ?
  if (_.isObject(data) && !_.isEmpty(data) && !_.isArray(data)) {
    // Omit rules only on object
    var omits = [ 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti' ];

    // Omit no needed property
    return _.omit(data, omits);
  }

  // Default statement
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
  // Is ready ?
  if (!this.isReady()) {
    // Error message
    this.logger.error('[ Jswt.decode ] - Cannot sign your data. Encrypt key is not set');

    // Invalid statement
    return false;
  }

  // Return sign data
  var decoded = jwt.decode(data);

  // Remove add item ?
  if (_.isBoolean(remove) && remove) {
    // Decoded data
    decoded = this.removeJwtKey(decoded);
  }

  // Default statement
  return decoded;
};

// Default export
module.exports = function (l) {
  // Is a valid logger ?
  if (_.isUndefined(l) || _.isNull(l)) {
    logger.warning('[ Jswt.constructor ] - Invalid logger given. Use internal logger');

    // Assign
    l = logger;
  }

  // Default statement
  return new Jswt(l);
};
