var c = require('../src')();

var data = { env: 'development',
  port: 3000,
  directory: 
   [ { models: './example/models' },
     { controllers: './example/controllers' },
     { views: './example/views' },
     { public: './example/public' },
     { icons: './example/public/icons' },
     { media: './example/public/media' } ],
  encrypt_key: { key: '6e67ae372ad6d85cfad1abc366823e28', type: 'hex' },
  a: 1,
  app: 
   { name: 'my AP DEV &&&&&& é\'é\'éèç!',
     stackError: false,
     session: { timeout: 30 } },
  express: 
   { jsonp: true,
     prettyHtml: true,
     filter: 
      { rules: 'json|text|javascript|css|html',
        by: 'Content-Type',
        level: 9 },
     multipart: true,
     methodOverride: 
      [ '_method',
        'X-HTTP-Method',
        'X-HTTP-Method-Override',
        'X-Method-Override' ],
     viewEngine: 'handlebars',
     session: 
      { enable: true,
        options: 
         { secret: '15Octobre2014',
           name: 'totot LGT 5',
           genuuid: true,
           proxy: true,
           resave: false,
           saveUninitialized: true,
           store: 
            { instance: 'mongo',
              uri: 'mongodb://user:pass@host:port/dbname',
              type: 'uri' },
           cookie: { path: '/', httpOnly: false, secure: true, maxAge: null },
           rolling: false } },
     vhost: 
      { enable: true,
        options: 
         { url: 'myhosturl.url',
           aliases: [ 'alias.myhosturl.url' ],
           subdomains: true,
           http: { redirect: { type: 301, url: 'www.myurl.url', port: 80 } } } },
     json: { inflate: true, limit: '100kb', strict: true, type: 'json' },
     urlencoded: 
      { extended: true,
        inflate: true,
        limit: '100kb',
        parameterLimit: 1000,
        type: 'urlencoded' },
     cookieParser: 
      { enable: false,
        secret: 'yocto-cookie-parser-secret-key',
        options: {} },
     security: 
      { csrf: { key: '_csrf', secret: 'yocto-secret-key' },
        csp: {},
        xframe: 'SAMEORIGIN',
        p3p: '_p3p',
        hsts: {},
        xssProtection: true } },
  host: '127.0.0.1',
  encrypt: { key: 'yocto-secret-key', type: 'hex' } };

// test part
var key  = '123132136545646';

// set algo
c.algorithm('AA4');
// set to HS384
//c.algorithm('HS384');
// set key
c.load().then(function() {
  if (c.setKey('fsdfds')) {
    var accessToken = c.generateAccessToken();
    console.log('AccessToken =>', accessToken);
    var signed  = c.sign(data, { algorithm : 'HS384' });
    console.log('Signed => ', signed);
    var decoded = c.decode(signed);
    console.log('Decoded => ', decoded);
    var decoded = c.decode(signed, true);
    console.log('Decoded WITH AUTO REMOVE => ', decoded);
    var verify = c.verify(signed).then(function (dec) {
      console.log('verify success =>', dec);
    }).catch(function (err) {
      console.log('verify error =>', err);
    });
  
  } else {
    // cannot set key
    console.log('cannot set key');
  }
}).catch(function (error) {
  console.log('e=>', error);
});


