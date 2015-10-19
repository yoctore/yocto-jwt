
angular.module('myApp', []).controller('formContr', ['$scope', '$http', function($scope, $http) {
  $scope.user = {};

  $scope.send = function(user) {

/*    var data = {
      email :  user.email,
      pwd   :  user.pwd
    };
*/

    var data = { 0 : 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtZXNzYWdlIjoiIHdlbGNvbWUgdG8gdGhlIGhvbWUiLCJpYXQiOjE0NDQ5MTEwNjN9.QiUMYoGomQNz8hFl_vjK2iXRmBg1odOhspqvrleb3Dc' };

    //stringify and encode data
    /*data = {
      data : $base64.encode(JSON.stringify(data))
    };*/

    console.log('\n --------------------- encoded data = ');
    console.log(data);
    console.log('-------------------- send request : ');
var token = '   eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiN2ZhYjBhNzctODJkYS00ZjVhLWEyOTktMTRjYThmZTE5YzljIiwiZGF0ZSI6MTQ0NTI1MTU0MDg2NSwia2V5IjoiYmJjZjg1ZGJiZWM2OTk2ZTYwZTUxZWQ4YWFiMjMxMjc5ODViMDFmMWJkNjRjMjkxZGNhMjM3NTRhNmMwYmE3Y2UwNDgzOGE5Nzg2ZDNiZjRkZTlhZDY1NWMxMTA1NDVmODMxYzdjYzZlZTM2ZDAwYTU3YzM4N2QxOThjMDYxNzRiMjIwNzEyZDc4ZDU2ODFmZGNkZWQ5NjQxNDk3ODdiNmIzZTg3MGYwNTcxN2QyYzI0YzUxOTMyNjgyOTU0NDQ1ODgxZjIxNWVlOTBhNjQ4YjNkZTkyY2FmNzI2OWJmNDdiMDhlMGEzYjY2NjIwZGQ4YWYwMmM1MmQ5OTM3YTI5ZmViZDY3Nzk3MDE3MDAxYmM5ZDgzMzhiYjc3YTYyNjM3YzM0MDcwZTE1ZTEzMzEyNGFkZmVjODFmNGRhM2RhZGQ3YTM4NDI5Mjk4NjE3N2ZiZGViMjU3Zjk3MzY1MmY4YjFmNTI2MGEzMmVmMDE3MGE2ZWQ4ZWUwMDYwZDljODRiN2Y0NDEyNjBjMGE2ZGRjYWY2MmUwNzQ5MWE1ZTIwNjk0ZTEwZTA4Y2E0OGI3OGI5MzY4NjU0ODZhM2MyMzI0NTVlYmMxMzJiMGUxYWVlY2FmZjJjYTE5OTcwZTMwYzIxOWMwM2U5M2VjMGUxNzZhNWExOWU5MTlmMDAyMmE4NWIzZDljNjk3YWYzZDUxZjBlM2I4NDNlNzlhODI0ZGIwNTRlNTAxOTIwZWFlMGIxODNjYTg5MTIzYTBmOGM0NmE0NTMxNDFhZjEwNzg4YTNjNjU2YmMzMTlmM2FjM2ZjODIwYThlMzg2ODM2OTg5MzZlZDRiNTQwMDU4ZWY3YzcwNjQzZjllYjE1YjFkOGRiNDQyNTljMjU1YTljY2E5MmJjZTNiODIyNmVmYmNjZmJjMWExM2RjMzcyZDUyMjQxNjNmYTJhZTdiYjJmYjYzZjRlZDE1NmE4ZDVhNDk5Mzc1NzUwYjY0MGU2NDcxNWE4Zjk4ZmFiN2VlNTFlYWVjNTQyMWQ4ODlhZGNiMmFiY2FmNTk3MTc2YzFmYTA0MWMzMjI2NGYyMGMyZTFkZGUyZDY2NzUxYzBjNGFmNDRhNWE3MmI5ZjFkYTkyOGQxYTUwYjVkMWIyNmZlOTkwNjcwMWU4YzhlNWRmZjFlMTgxNmUyOTc5OGVkNDc5NzFlODQwYTM1ZjhkNGU0NzkwM2ZmNWJlM2NmMTc2MzM2ODMwMjU1OSIsImlhdCI6MTQ0NTI1MTU0MCwiZXhwIjoxNDQ1MjUxODQwfQ.C8if8t9_XWdpSY5Qd5DPQFQuGyOjX-WEkaZMA0yAFfg';
  $http({
    url: 'http://localhost:3000/login',
    method: 'POST',
    data : data,
    headers : {
      'x-jwt-access-token' : token
    },
    transformResponse: function(value) {
      console.log('--- Response ... encrypted value : ');
      console.log(value);

      return value;//JSON.parse($base64.decode(value));
    }
  }).then(function(response) {
      console.log(' ----- success promise, data decrypted:');
      console.log(response.data);

    }, function(response) {
      console.log(' ----- failed promise, data decrypted');
      console.log(response.data);
    });
  };
}]);
