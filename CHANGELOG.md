## 3.0.0 (2018-02-16)

- Major update of all dependencies
- Update node version engine to >= 8.9.4

## 2.0.0 (2016-07-26)
- Bug fixe :
  - use trimStart() instead of trimLeft()

## 2.0.0 (2016-07-26)
- Bug fixe :
  - if autodecrypt() fail, the next() middleware was called, now an response HTTP 403 will be send
- Improvement :
  - All request should have an header 'x-jwt-access-token' even GET request expect allowedRoutes wich token was not required.
  - Migrate to Lodash -> 4.14.0

## 1.7.1 (2016-07-20)
- Bug fixe :
 - Use lockFile to avoid error on cluster mode

## 1.7.0 (2016-07-20)
- Improvement :
 - On initialize pem, the file was write in a file on cwd() folder. It used for share pem file on cluster mode.

## 1.6.0 (2016-06-07)

- Bug Fixe :
  - When add an allowerRoutes, if string is not an RegExp, the string will be regexpected

## 1.6.0 (2016-05-27)

- Now route can be ignore to jwt validation -> addAllowedRoutes()
- Ip will be trimed for ':::ffff:'
- Add more log information
- Update package.json
- Change arguments for method ipIsAllowed(ip) -> ip is now a string

## 1.4.7 (2015-12-07)

- Change test on wilward '*' definition

## 1.4.5 (2015-12-07)

- Add wildcard for allow website access

## 1.4.4 (2015-12-04)

- Bug on array to remove jwt property on removeJWtKey

## 1.4.2 (2015-12-03)

- Go to next when body is empty patch / post request

## 1.4.2 (2015-12-01)

- Remove an unused filter

## 1.4.0 (2015-10-20)

- update context usate
- add and utility method to filter by ip

## 1.3.0 (2015-10-20)

- Test is given key is a file without the second arguments.

## 1.2.0 (2015-10-20)

- Add test on autoDecrypt method to ignore frontapp when we can share a key to not process verify.

## 1.1.0 (2015-10-19)

- Add PEM and cert usage on get accessToken

## 1.0.0 (2015-10-16)

- Add auto decrypt method
- Fix minor bugs on generateAccessToken
- Prepare to npm publish

## 0.1.0 > 0.5.0 (2015-10-14)

- Rewrite all code module
- Add jwt module for encryption
- Add middleware method for express for :  auto encode/decode for jsonp request
- Add middleware method for access checking
- Add auto encode/decode for json request
- Add generateAccessToken method
