/* yocto-jwt - Manage jwt token, and encrypt/decrypt all request based on jwt webtoken and cert - V1.4.9 */
"use strict";function Pem(){this.state=!1}var pem=require("pem"),Q=require("q"),_=require("lodash");Pem.prototype.processJwt=function(){var a=Q.defer();return pem.createCertificate({days:1,selfSigned:!0},function(b,c){var d={};b?a.reject(b):(_.merge(d,c),pem.getPublicKey(c.certificate,function(b,c){b?a.reject(b):(_.merge(d,c),this.state=!0,a.resolve(d))}.bind(this)))}.bind(this)),a.promise},Pem.prototype.verify=function(a,b){var c=Q.defer();return pem.getModulus(a,function(a,d){a?c.reject(a):pem.getModulus(b,function(a,b){a||d.modulus!==b.modulus?c.reject(a?a:"certificate not match with given key"):c.resolve()})}),c.promise},Pem.prototype.isReady=function(){return this.state},module.exports=new Pem;