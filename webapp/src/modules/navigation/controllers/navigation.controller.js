angular.module('bricata.ui.navigation')
    .controller('NavigationController',
    ['$scope', 'BricataUris', 'CommonNavigationService', 'topMenuLinks',
    function($scope, BricataUris, CommonNavigationService, topMenuLinks) {

        // Initializing the main top navigation links object
        $scope.mainNavLinks = topMenuLinks.getLinks(BricataUris);

        $scope.navigationClicked = function(url, linkType) {
            CommonNavigationService.navigateTo(url, linkType);
        };

        $scope.isActiveLink = function (linkName) {
            return CommonNavigationService.isThisCurrentLocation(linkName);
        };

    }]);
