
angular.module('myApp', []).controller('formContr', ['$scope', '$http', function($scope, $http) {
  $scope.user = {};

  $scope.send = function(user) {

    var data = {
      email :  user.email,
      pwd   :  user.pwd
    };

    //stringify and encode data
    /*data = {
      data : $base64.encode(JSON.stringify(data))
    };*/

    console.log('\n --------------------- encoded data = ');
    console.log(data);
    console.log('-------------------- send request : ');
var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiODE3YWFjZjMtMDg5My00ZWMxLWExYWYtNzE4ZmNkYmNhNDE1IiwiZGF0ZSI6MTQ0NDg1Nzk5ODYzMCwiaWF0IjoxNDQ0ODU3OTk4fQ.bRBdIXgo_30Vm5WgeHaw239MJxdqtomj4_TP9lCps6U';
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
