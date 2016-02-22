angular.module('bricata.ui.header')
    .controller('headerBarController', ['$scope', 'BricataUris',
    function($scope, BricataUris) {

        $scope.BricataUris = BricataUris;

    }]);
