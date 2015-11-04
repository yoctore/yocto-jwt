/* yocto-jwt - Manage jwt token, and encrypt/decrypt all request based on jwt webtoken and cert - V1.3.1 */
"use strict";function Jswt(a){this.logger=a,this.encryptKey="",this.secureKeys={publicKey:"",clientKey:"",certificate:"",serviceKey:"",csr:""},this.algorithms=["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"],this.usedAlgorithm="HS256",this.headers={access:"x-jwt-access-token",encode:"x-jwt-decode-token",ignore:"x-jwt-ignore-decrypt"}}var logger=require("yocto-logger"),uuid=require("uuid"),fs=require("fs"),path=require("path"),jwt=require("jsonwebtoken"),_=require("lodash"),Q=require("q"),utils=require("yocto-utils"),crypto=require("crypto"),pem=require("./modules/pem"),fs=require("fs");Jswt.prototype.load=function(){var a=Q.defer(),b=this;return pem.processJwt().then(function(c){_.merge(b.secureKeys,c),a.resolve()})["catch"](function(b){a.reject(b)}),a.promise},Jswt.prototype.getKey=function(){return this.encryptKey},Jswt.prototype.getPrivateKey=function(){return this.secureKeys.clientKey},Jswt.prototype.getPublicKey=function(){return this.secureKeys.publicKey},Jswt.prototype.getAccessKey=function(){if(!this.isReady())return this.logger.error(["[ Jswt.getAccessKey ] -","Cannot get access key. Encrypt key is not set"].join(" ")),!1;if(!pem.isReady())return this.logger.error(["[ Jswt.getAccessKey ] -","Cannot get access key. Certificate was not genrated."].join(" ")),!1;var a=crypto.createHash("sha1").update(this.getPublicKey()).digest("hex");return utils.crypto.encrypt(a,this.getPublicKey())},Jswt.prototype.generateAccessToken=function(a){if(!this.isReady())return this.logger.error(["[ Jswt.generateAccessToken ] -","Cannot generate access token. Encrypt key is not set"].join(" ")),!1;if(!pem.isReady())return this.logger.error(["[ Jswt.generateAccessToken ] -","Cannot generate access token. Certificate was not genrated."].join(" ")),!1;var b=this.getAccessKey();a=_.isString(a)&&!_.isEmpty(a)?a:uuid.v4();var c=a===b?"1h":"5m";return this.sign({name:a,date:Date.now(),key:b},{expiresIn:c})},Jswt.prototype.isAuthorized=function(a){return function(b,c,d){if(!_.isObject(b)||!_.isObject(c))return d();if(!b.is("application/json"))return d();a.logger.debug("[ Jswt.isAuthorized ] - checking access on server.");var e=b.get(a.headers.access.toLowerCase());return _.isUndefined(e)?c.status(403).send("You d'ont have access to this ressource.").end():void a.verify(e).then(function(b){var e=crypto.createHash("sha1").update(a.getPublicKey()).digest("hex"),f=utils.crypto.decrypt(e,b.key.toString());return f===!1?c.status(403).send("Invalid Token."):void pem.verify(a.secureKeys.certificate,a.secureKeys.clientKey).then(function(){return a.logger.debug("[ Jswt.isAuthorized ] - given token seems to be valid"),d()})["catch"](function(b){return a.logger.error(["[ Jswt.isAuthorized ] - ",b].join(" ")),c.status(403).send("Invalid Token.")})})["catch"](function(a){return _.has(a,"expiredAt")?c.status(403).send("Token has expired."):c.status(403).send(["Cannot validate your access.","Please retry."].join(" ")).end()})}},Jswt.prototype.autoEncryptRequest=function(a){return function(b,c,d){if(_.isObject(b)&&_.isObject(c)){var e=["json","jsonp"];_.each(e,function(b){var d=c[b];c[b]=function(b){return a.logger.debug(["[ Jswt.autoEncryptRequest ] - Receiving new data to encrypt : ",utils.obj.inspect(b)].join(" ")),d.call(this,[a.sign(b)])}},a)}return d()}},Jswt.prototype.autoDecryptRequest=function(a){return function(b,c,d){if(!b.is("application/json"))return d();if(_.has(b.headers,a.headers.ignore)&&b.headers[a.headers.ignore])return a.logger.debug("[ Jswt.autoDecryptRequest ] - ignore header was sent. got to next"),d();a.logger.debug(["[ Jswt.autoDecryptRequest ] - Receiving new data to decrypt : ",utils.obj.inspect(b.body)].join(" "));var e=b.body;_.isObject(b.body)&&!_.isEmpty(b.body)&&(e=_.first(b.body)),a.verify(e).then(function(c){b.body=a.removeJwtKey(c),d()})["catch"](function(b){a.logger.error(["[ Jswt.autoDecryptRequest ] -",b].join(" ")),d()})}},Jswt.prototype.algorithm=function(a){return _.isUndefined(a)||_.isNull(a)||(_.isString(a)&&_.includes(this.algorithms,a)?(this.usedAlgorithm=a,this.logger.info(["[ Jswt.algorithm ] - set algorithm to",a].join(" "))):this.logger.warning(["[ Jswt.algorithm ] - invalid algorithm given. Keep algorithm to",this.usedAlgorithm].join(" "))),this.usedAlgorithm},Jswt.prototype.setKey=function(a){var b=!1;if(_.isString(a)&&!_.isEmpty(a)){var c=a;path.isAbsolute(a)||(a=path.normalize([process.cwd(),a].join("/")));try{var d=fs.statSync(a);b=d.isFile()}catch(e){this.logger.warning("[ Jswt.setKey ] - key is not a file. Process key like a string.")}return b&&(a=fs.readFileSync(a)),this.encryptKey=b?a:c,this.logger.info("[ Jswt.setKey ] - Setting key done."),_.isString(this.encryptKey)&&!_.isEmpty(this.encryptKey)}return this.logger.warning("[ Jswt.setKey ] - Invalid key or path given."),!1},Jswt.prototype.setPrivateKey=function(a){return _.isString(a)||_.isEmpty(a)?!1:(this.privateKey=a,!0)},Jswt.prototype.verify=function(a,b){var c=this,d=Q.defer();this.isReady()||(this.logger.error("[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set"),d.reject("[ Jswt.verify ] - Cannot sign your data. Encrypt key is not set"));try{jwt.verify(a,this.encryptKey,function(a,e){a?(c.logger.error(["[ Jswt.verify ] - An error occured :",a.message,a.expiredAt||""].join(" ")),d.reject(a)):(_.isBoolean(b)&&b&&(e=c.removeJwtKey(e)),d.resolve(e))})}catch(e){this.logger.error(["[ Jswt.verify ] - Cannot cerify your data :",e].join(" ")),d.reject("Cannot cerify your data.")}return d.promise},Jswt.prototype.isReady=function(){return _.isString(this.encryptKey)&&!_.isEmpty(this.encryptKey)},Jswt.prototype.sign=function(a,b){return this.isReady()?(b=b||{},_.has(b,"algorithm")&&(_.includes(this.algorithms,b.algorithm)?this.logger.info(["[ Jswt.sign ] - custom valid algorithm given in options.","Use",b.algorithm,"for encryption"].join(" ")):_.merge(b,{algorithm:this.algorithm()})),jwt.sign(a,this.encryptKey,b)):(this.logger.error("[ Jswt.sign ] - Cannot sign your data. Encrypt key is not set"),!1)},Jswt.prototype.removeJwtKey=function(a){if(_.isObject(a)&&!_.isEmpty(a)){var b=["iss","sub","aud","exp","nbf","iat","jti"];_.each(b,function(b){a=_.omit(a,b)})}return a},Jswt.prototype.decode=function(a,b){if(!this.isReady())return this.logger.error("[ Jswt.decode ] - Cannot sign your data. Encrypt key is not set"),!1;var c=jwt.decode(a);return _.isBoolean(b)&&b&&(c=this.removeJwtKey(c)),c},module.exports=function(a){return(_.isUndefined(a)||_.isNull(a))&&(logger.warning("[ Jswt.constructor ] - Invalid logger given. Use internal logger"),a=logger),new Jswt(a)};