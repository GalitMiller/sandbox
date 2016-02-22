angular.module("bricata.ui.signaturecategories")
    .directive("signatureCategoriesHeader", ["CommonNavigationService",
    function (CommonNavigationService) {

        return {
            restrict: 'E',
            templateUrl: 'modules/signaturecategories/views/signatureCategoriesNavigation.html',
            link: function(scope) {
                scope.totalSignatureCategoriesFound = 0;
                scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                    scope.totalSignatureCategoriesFound = totalCount;
                });

                scope.openCreateSignatureCategoryWizard = function() {
                    CommonNavigationService.navigateToSignatureCategoriesWizardPage();
                };
            }
        };
    }]);