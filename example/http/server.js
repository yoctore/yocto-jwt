var _           = require('lodash');
var express     = require('express');
var app         = express();
var logger      = require('yocto-logger');
var bodyParser  = require('body-parser');
var cors        = require('cors');
var jwt         = require('../../src/')(logger);
var path        = require('path');
var base        = path.normalize(process.cwd());

// view engine setup
app.set('views', './views');
app.set('view engine', 'jade');
app.set('view options', ({ layout : true }));

app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));

app.use(cors());
//app.use(decryptor.decryptor);
//app.use(decryptor.encryptor());
jwt.setKey('12345');
console.log('A TOKEN => ', jwt.generateAccessToken());
app.use(jwt.isAuthorized(jwt));
app.use(jwt.autoEncryptRequest(jwt));
app.use(jwt.autoDecryptRequest(jwt));

// Configure app to angular and all bower_components
app.use('/public', express.static(base + '/public'));
app.use('/bower_components',  express.static(base + '/bower_components'));

// Request to connect
// email = 'toto' and pwd == 'aaaa'
app.post('/login', function(req, res) {
  console.log('B in route =>', req.body);
  if (req.body.email == 'toto' && req.body.pwd == 'aaaa') {
    console.log("connect success");

    res.status(200).jsonp({ message : 'connect success' });

  } else {
    console.log("connect failed");
    res.status(400).json({ message : 'connect Failed' });
  }
});

app.get('/home', function(req, res, next) {
  res.status(200).jsonp({ message :' welcome to the home' });
});

// Return connect page
app.get('/connect', function(req, res, next) {
  res.render('connect');
});

var server = app.listen(3000, function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('app start on port : ' +  port);
});
