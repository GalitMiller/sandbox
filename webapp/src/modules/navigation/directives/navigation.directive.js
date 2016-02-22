angular.module("bricata.ui.navigation")
    .directive("mainNavigation",
        function() {
        return {
            restrict : 'E',
            controller: 'NavigationController',
            templateUrl : 'modules/navigation/views/navigation.html'
        };
    });