/* yocto-jwt - Encrypt and decrypt all request based on jwt webtoken - V1.0.0 */
"use strict";function Jswb(a){this.logger=a,this.encryptKey="",this.algorithms=["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"],this.usedAlgorithm="HS256",this.headers={access:"x-jwt-access-token",encode:"x-jwt-decode-token"}}var logger=require("yocto-logger"),uuid=require("uuid"),fs=require("fs"),path=require("path"),jwt=require("jsonwebtoken"),_=require("lodash"),Q=require("q"),utils=require("yocto-utils"),crypto=require("crypto");Jswb.prototype.getKey=function(){return this.encryptKey},Jswb.prototype.getAccessKey=function(){var a=crypto.createHash("sha1").update(this.getKey()).digest("hex");return utils.crypto.encrypt(a,this.getKey())},Jswb.prototype.generateAccessToken=function(a){return this.isReady()?(a=_.isString(a)&&!_.isEmpty(a)?a:uuid.v4(),this.sign({name:a,date:Date.now(),key:this.getAccessKey()})):(this.logger.error(["[ Jswb.generateAccessToken ] -","Cannot sign your data. Encrypt key is not set"].join(" ")),!1)},Jswb.prototype.isAuthorized=function(a){return function(b,c,d){if(!_.isObject(b)||!_.isObject(c))return d();if(!b.is("application/json"))return d();a.logger.debug("[ Jswb.algorithm ] - checking access on server.");var e=b.get(a.headers.access.toLowerCase());return _.isUndefined(e)?c.status(403).send("You d'ont have access to this ressource.").end():void a.verify(e).then(function(b){var e=crypto.createHash("sha1").update(a.getKey()).digest("hex"),f=utils.crypto.decrypt(e,b.key.toString());return f===a.getKey()?d():c.status(403).send("Invalid Token.")})["catch"](function(a){return _.has(a,"expiredAt")?c.status(403).send("Token has expired."):c.status(403).send(["Cannot validate your access.","Please retry."].join(" ")).end()})}},Jswb.prototype.autoEncryptRequest=function(a){return function(b,c,d){if(_.isObject(b)&&_.isObject(c)){var e=["json","jsonp"];_.each(e,function(b){var d=c[b];c[b]=function(b){return a.logger.debug(["[ Jswb.autoEncryptRequest ] - Receiving new data to encrypt : ",utils.obj.inspect(b)].join(" ")),200===this.statusCode&&this.header(a.headers.encode.toLowerCase(),a.getKey()),d.call(this,[a.sign(b)])}},a)}return d()}},Jswb.prototype.autoDecryptRequest=function(a){return function(b,c,d){if(!b.is("application/json"))return d();a.logger.debug(["[ Jswb.autoDecryptRequest ] - Receiving new data to decrypt : ",utils.obj.inspect(b.body)].join(" "));var e=b.body;_.isObject(b.body)&&!_.isEmpty(b.body)&&(e=_.first(b.body)),a.verify(e).then(function(c){b.body=a.removeJwtKey(c),d()})["catch"](function(b){a.logger.error(["[ Jswb.autoDecryptRequest ] -",b].join(" ")),d()})}},Jswb.prototype.algorithm=function(a){return _.isUndefined(a)||_.isNull(a)||(_.isString(a)&&_.includes(this.algorithms,a)?(this.usedAlgorithm=a,this.logger.info(["[ Jswb.algorithm ] - set algorithm to",a].join(" "))):this.logger.warning(["[ Jswb.algorithm ] - invalid algorithm given. Keep algorithm to",this.usedAlgorithm].join(" "))),this.usedAlgorithm},Jswb.prototype.setKey=function(a,b){return b=_.isBoolean(b)?b:!1,_.isString(a)&&!_.isEmpty(a)?(b&&(path.isAbsolute(a)||(a=path.normalize([process.cwd(),a].join("/"))),a=fs.readFileSync(a)),this.encryptKey=a,this.logger.info("[ Jswb.setKey ] - Setting key done."),_.isString(this.encryptKey)&&!_.isEmpty(this.encryptKey)):(this.logger.warning("[ Jswb.setKey ] - Invalid key or path given."),!1)},Jswb.prototype.verify=function(a,b){var c=this,d=Q.defer();return this.isReady()||(this.logger.error("[ Jswb.verify ] - Cannot sign your data. Encrypt key is not set"),d.reject("[ Jswb.verify ] - Cannot sign your data. Encrypt key is not set")),jwt.verify(a,this.encryptKey,function(a,e){a?(c.logger.error(["[ Jswb.verify ] - An error occured :",a.message,a.expiredAt||""].join(" ")),d.reject(a)):(_.isBoolean(b)&&b&&(e=c.removeJwtKey(e)),d.resolve(e))}),d.promise},Jswb.prototype.isReady=function(){return _.isString(this.encryptKey)&&!_.isEmpty(this.encryptKey)},Jswb.prototype.sign=function(a,b){return this.isReady()?(b=b||{},_.has(b,"algorithm")&&(_.includes(this.algorithms,b.algorithm)?this.logger.info(["[ Jswb.sign ] - custom valid algorithm given in options.","Use",b.algorithm,"for encryption"].join(" ")):_.merge(b,{algorithm:this.algorithm()})),jwt.sign(a,this.encryptKey,b)):(this.logger.error("[ Jswb.sign ] - Cannot sign your data. Encrypt key is not set"),!1)},Jswb.prototype.removeJwtKey=function(a){if(_.isObject(a)&&!_.isEmpty(a)){var b=["iss","sub","aud","exp","nbf","iat","jti"];_.each(b,function(b){a=_.omit(a,b)})}return a},Jswb.prototype.decode=function(a,b){if(!this.isReady())return this.logger.error("[ Jswb.decode ] - Cannot sign your data. Encrypt key is not set"),!1;var c=jwt.decode(a);return _.isBoolean(b)&&b&&(c=this.removeJwtKey(c)),c},module.exports=function(a){return(_.isUndefined(a)||_.isNull(a))&&(logger.warning("[ Jswb.constructor ] - Invalid logger given. Use internal logger"),a=logger),new Jswb(a)};