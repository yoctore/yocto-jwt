var _           = require('lodash');
var logger      = require('yocto-logger');

/**
 * Middleware encryptor
 *
 * @date 05/08/2015
 */



/**
 * Decrypt each data that present in req.body
 * @return {[type]} [description]
 */
exports.decryptor = function(req, res, next) {
  console.log(' --- new request, encrypted body is : ');

  var reg = new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$');

  var buff ;
  _.each(req.body, function(val, key) {
    if (val.match(reg)) {
      //FIXME : Test ne fonctionne pas coréctement
      console.log( key  + ' match ..');
      buff = new Buffer(val, 'base64');
      req.body[key] = buff.toString();
    }
    else {
      console.log( key + ' is not a encode base 64');
    }
  });

  next();
};

/**
 * Encrypt data that be send to client except render request
 * @return {[type]} [description]
 */
exports.encryptor = function() {

  return function(req, res, next) {

    //console.log(res.req);

    //NOTE : vérifier comportement
    //Determine if is a render response
    // if (!res.req._body) {
    //   //res.req._body is not define so it's a render response
    //   return next();
    // }

    if (arguments.length !== 3 || !_.isObject(req) || !_.isObject(res) || !_.isObject(next)) {
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

      logger.debug('encryptedData : ');
      console.log(encryptedData);
      return res.realSend(encryptedData);
    };

    next();
  };
};
