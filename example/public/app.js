

// declare a module
var myApp = angular.module('myApp', ['base64']);


myApp.controller('formContr', ['$scope', '$http', '$base64', function($scope, $http, $base64) {
  $scope.user = {};

  $scope.send = function(user) {

    var data = {
      email :  user.email,
      pwd   :  user.pwd
    };

    //stringify and encode data
    data = {
      data : $base64.encode(JSON.stringify(data))
    };

    console.log('\n --------------------- encoded data = ');
    console.log(data);
    console.log('-------------------- send request : ');

  $http({
    url: 'http://localhost:3000/login',
    method: 'POST',
    data : data,
    transformResponse: function(value) {
      console.log('--- Response ... encrypted value : ');
      console.log(value);

      return JSON.parse($base64.decode(value));
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
