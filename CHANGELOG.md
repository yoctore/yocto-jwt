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
