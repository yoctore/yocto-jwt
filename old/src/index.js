var _           = require('lodash');
var logger      = require('yocto-logger');

/**
 * Midllewares for express 4+ to auto encrypt-decrypt base64
 *
 * @date 05/08/2015
 * @author Cedric Balard <cedric#yocto.re>
 */

/**
 * Decrypt each data that present in req.body
 */
exports.decryptor = function(req, res, next) {
  logger.debug('-------------------------------');
  logger.debug('[ decryptor ] - new incoming request, encrypted body is : ');
  logger.debug(JSON.stringify(req.body));

  // Reg exp to base64
  var reg = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

  _.each(req.body, function(val, key) {
    // Check if is an base64 with regexp and test if it's multiple of 4
    if (val.match(reg) && val.length % 4 === 0) {
      var buff          = new Buffer(val, 'base64');
      var decryptedVal  = buff.toString();

      try {
        // Test if is an object
        decryptedVal = JSON.parse(decryptedVal);
        _.each(decryptedVal, function(valA, keyA) {
          req.body[keyA] = valA;
        });
      } catch (e) {
        // Is not an object
        req.body[key] = decryptedVal;
      }
    }
    else {
      logger.debug( key + ' is not a encode base 64');
    }
  });
  logger.debug('[ decryptor ]  - decrypted body is : ');
  logger.debug(req.body);
  next();
};


/**
 * Encrypt data that will be send to client except render request
 */
exports.encryptor = function() {

  return function(req, res, next) {

    if (arguments.length !== 3 || !_.isObject(req) || !_.isObject(res)|| !_.isObject(next)) {
      return next();
    }

    var responseObj = {
      headers : res._headers
    };

    //Save current Method
    res.realSend = res.send;

    //Overide jsonp
    res.jsonp = function(statusOrBody, body) {
      if (arguments.length === 2) {
        responseObj.status = statusOrBody;
        responseObj.body   = body;
      } else {
        responseObj.status = res.statusCode;
        responseObj.body   = statusOrBody;
      }

      //encrypte the data
      var b = new Buffer(JSON.stringify(responseObj.body));
      var encryptedData = b.toString('base64');

      logger.debug('[ encryptor ] - encryptedData : ');
      logger.debug(encryptedData);

      //Do the send
      return res.realSend(encryptedData);
    };

    next();
  };
};
