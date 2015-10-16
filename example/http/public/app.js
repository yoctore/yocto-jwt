
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
var token = '  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiMmUyMjg1YjUtNjQyMS00MWNhLWEzMmMtM2RmYTE2NzJlZTA3IiwiZGF0ZSI6MTQ0NDkwMzcyMDg3Mywia2V5IjoiN2MzYzM5ZDc4MTgwYTk4MGNjOTQ3MGM1MjFlMjk5NGEiLCJpYXQiOjE0NDQ5MDM3MjB9.YmAT_iRVYU4JpbUn1N1G03guwthwT4Tk3n0UlVGbnEE';
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
