[![NPM](https://nodei.co/npm/yocto-jwt.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/yocto-jwt/)

![alt text](https://david-dm.org/yoctore/yocto-jwt.svg "Dependencies Status")
[![Code Climate](https://codeclimate.com/github/yoctore/yocto-jwt/badges/gpa.svg)](https://codeclimate.com/github/yoctore/yocto-jwt)
[![Test Coverage](https://codeclimate.com/github/yoctore/yocto-jwt/badges/coverage.svg)](https://codeclimate.com/github/yoctore/yocto-jwt/coverage)
[![Issue Count](https://codeclimate.com/github/yoctore/yocto-jwt/badges/issue_count.svg)](https://codeclimate.com/github/yoctore/yocto-jwt)
[![Build Status](https://travis-ci.org/yoctore/yocto-jwt.svg?branch=master)](https://travis-ci.org/yoctore/yocto-jwt)

## Overview

This module is a part of yocto node modules for NodeJS.

Please see [our NPM repository](https://www.npmjs.com/~yocto) for complete list of available tools (completed day after day).

This module manage web token process on your app or can use like a crypt tools.

We can use it like a middleware to encrypt and decrypt all json request just with a preconfigured key.

You can also check for each json request if request is allow.

**!!! IMPORTANT !!! Please read [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) for key usage.**

This module use [pem](https://www.npmjs.com/package/pem) package for private / web key usage

## Witch type of key works ?

Your can use a simple secret key or a cert file, like explain [here](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options)

For more details see usage examples below.

## Algorithms supported

Array of supported algorithms. The following algorithms are currently supported.

| Algorithm | Digital Signature or MAC Algorithm                 |
|:---------:|----------------------------------------------------|
|   HS256   | HMAC using SHA-256 hash algorithm                  |
|   HS384   | HMAC using SHA-384 hash algorithm                  |
|   HS512   | HMAC using SHA-512 hash algorithm                  |
|   RS256   | RSASSA using SHA-256 hash algorithm                |
|   RS384   | RSASSA using SHA-384 hash algorithm                |
|   RS512   | RSASSA using SHA-512 hash algorithm                |
|   ES256   | ECDSA using P-256 curve and SHA-256 hash algorithm |
|   ES384   | ECDSA using P-384 curve and SHA-384 hash algorithm |
|   ES512   | ECDSA using P-521 curve and SHA-512 hash algorithm |

## Classic usage

```javascript

var c = require('yocto-jwt');

// our data
var data = {
  env       : 'development',
  port      : 3000,
  directory : [
    { models       : './example/models' },
    { controllers  : './example/controllers' },
    { views        : './example/views' },
    { public       : './example/public' },
    { icons        : './example/public/icons' },
    { media        : './example/public/media' }
  ],
  a: 1,
  foo : 'bar'
};

// KEY SETTING part
var key  = 'MY_JWT_KEY_OR_CERT_FILE';

// set algo
//c.algorithm('HS384');

// set key
if (c.setKey(key)) {
  // signed process
  var signed  = c.sign(data, { algorithm : 'HS384' });
  console.log('Signed => ', signed);

  // decode proess
  var decoded = c.decode(signed);
  console.log('Decoded => ', decoded);

  // decode with auto remove of jwt properties (iat, etc ...)
  var decoded = c.decode(signed, true);
  console.log('Decoded WITH AUTO REMOVE => ', decoded);

  // verify signature process
  var verify = c.verify(signed).then(function (dec) {
    console.log('verify success =>', dec);
  }).catch(function (err) {
    console.log('verify error =>', err);
  });
} else {
  // cannot set key
  console.log('cannot set key');
}
```

## Middleware usage

If you are using AngularJs you can use our middleware [yocto-angular-jwt](https://gitlab.com/yocto-angular-services/yocto-angular-jwt.git)
that provide to you a tool that can manage request processed with [yocto-jwt](https://www.npmjs.com/package/yocto-jwt)

```javascript
var jwt = require('yocto-jwt');
var express     = require('express');
var app         = express();

// setup your express ...

// set key
jwt.setKey('12345');

// enable auto encrypt json request
app.use(jwt.autoEncryptRequest());

// enable auto decrypt json request
app.use(jwt.autoDecryptRequest());
```

## How to auto filter json request access

To use this feature your front app must send with current json request a specific header : `x-jwt-access-token`.

This header must contain a valid token generate by the server.

```javascript
var jwt = require('yocto-jwt');
var express     = require('express');
var app         = express();

// setup your express ...

jwt.load().then(function() {
  // set key
  jwt.setKey('12345');

  // add autorize middleware for automatic check
  app.use(jwt.isAuthorized());

  // enable auto encrypt json request
  app.use(jwt.autoEncryptRequest());

  // enable auto decrypt json request
  app.use(jwt.autoDecryptRequest());
}).catch(function (error) {
  console.log(error);
});
```

You can also use our AngularJs middleware [yocto-angular-jwt](https://gitlab.com/yocto-angular-services/yocto-angular-jwt.git)
that provide to you a tool that can manage request processed with [yocto-jwt](https://www.npmjs.com/package/yocto-jwt)

## How to generate an access token

You can also setup a route on your node server to refresh your access token.

In this tools you must call `generateAccessToken` method to retrieve a new token.

By default a token is valid 5 minutes.

```javascript
var jwt = require('yocto-jwt');

var token = jwt.generateAccessToken();
```

## How allow ip access

By default only localhost are allowed (::1 & 127.0.0.1)

```javascript
var jwt = require('yocto-jwt');
var express     = require('express');
var app         = express();

// setup your express ...

jwt.load().then(function() {
  // set key
  jwt.setKey('12345');
  // set ips rang ip is allowed and check with netmask
  jwt.allowedIps([ '10.0.0.0/12', '192.168.1.134' ]);
  // add autorize middleware for automatic check
  app.use(jwt.isAuthorized());

  // enable auto encrypt json request
  app.use(jwt.autoEncryptRequest());

  // enable auto decrypt json request
  app.use(jwt.autoDecryptRequest());
}).catch(function (error) {
  console.log(error);
});
```
## How allow route without jwt verification

By default none route is allowed.
If the url of the request match an *allowedRoute* the ip of the caller will not be check

```javascript
var jwt = require('yocto-jwt');
var express     = require('express');
var app         = express();

// setup your express ...
jwt.load().then(function() {
  // set key
  jwt.setKey('12345');

  // set allowed routes
  jwt.addAllowedRoutes([ /auth\/connect/, /status/ ]);

  // add autorize middleware for automatic check
  app.use(jwt.isAuthorized());

  // enable auto encrypt json request
  app.use(jwt.autoEncryptRequest());

  // enable auto decrypt json request
  app.use(jwt.autoDecryptRequest());
}).catch(function (error) {
  console.log(error);
});
```

## Next Step

- Add method to change refresh delay & more
