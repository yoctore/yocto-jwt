# yocto-http-encrypt

> Midllewares for express 4+ to auto encrypt-decrypt base64


This two middlewares encrypt and decrypt all request that contains object.

Method encryption is base64.

Only **jsonp**

## Getting started

First require the module :
```js
var decryptor   = require('yocto-http-encryp');
```

And set the two middleware to run with express :

```js
var express     = require('express');
var app         = express();

app.use(decryptor.decryptor);
app.use(decryptor.encryptor());

```

## More details

### decryptor.decryptor

This middleware decrypt each data contains in req.body. If the the result is an jsonified object, the result will be parsed, and each keys will be added on req.body.

### decryptor.encryptor

This middleware encrypt each data contains in req.body. If needed data can be stringify with *JSON.stringify* and after encrypted.
