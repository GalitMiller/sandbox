angular.module("bricata.ui.header")
    .directive("headerBar",
        function() {
        return {
            restrict : 'E',
            controller: 'headerBarController',
            templateUrl : 'modules/header/views/header.html'
        };
    });