angular.module("bricata.ui.severity")
    .directive("severitiesHeaderNavigation", [ "CommonNavigationService",
        function (CommonNavigationService) {

            return {
                restrict: 'E',
                templateUrl: 'modules/severity/views/severities-header.html',
                link: function(scope) {
                    scope.totalSeveritiesFound = 0;

                    scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                        scope.totalSeveritiesFound = totalCount;
                    });

                    scope.navToWizardPage = function() {
                        CommonNavigationService.navigateToSeverityWizardPage();
                    };
                }
            };
        }]);