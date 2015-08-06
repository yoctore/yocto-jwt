var _           = require('lodash');
var logger      = require('yocto-logger');
/**
 * Decrypt each data that present in req.body
 * @return {[type]} [description]
 */
exports.decryptor = function(req, res, next) {
  logger.debug('-------------------------------');
  logger.debug('[ decryptor ] - new incoming request, encrypted body is : ');
  console.log(req.body);

  // Reg exp to base64
  var reg = new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$');

  _.each(req.body, function(val, key) {
    // NOTE : a vérifier ne fonctionne peut etre pas coréctement
    if (val.match(reg)) {
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
      console.log( key + ' is not a encode base 64');
    }
  });
  logger.debug('[ decryptor ]  - decrypted body is : ');
  console.log(req.body);
  next();
};


/**
 * Encrypt data that be send to client except render request
 * @return {[type]} [description]
 */
exports.encryptor = function() {

  return function(req, res, next) {

    if (arguments.length !== 3 || !_.isObject(req) || !_.isObject(res)|| !_.isObject(next)) {
      return next();
    }

    var responseObj = {
      headers : res._headers
    };

    res.realSend = res.send;

    res.jsonp = function(statusOrBody, body) {
      if (arguments.length === 2) {
        responseObj.status = statusOrBody;
        responseObj.body   = body;
      } else {
        responseObj.status = res.statusCode;
        responseObj.body   = statusOrBody;
      }

      var b = new Buffer(JSON.stringify(responseObj.body));
      var encryptedData = b.toString('base64');

      logger.debug('[ encryptor ] - encryptedData : ');
      console.log(encryptedData);
      return res.realSend(encryptedData);
    };

    next();
  };
};
