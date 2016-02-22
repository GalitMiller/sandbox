angular.module("bricata.ui.sensors")
    .directive("inactiveSensorsHeader", [
        function () {

            return {
                restrict: 'E',
                templateUrl: 'modules/sensors/views/inactive-sensors-header.html',
                link: function(scope) {
                    scope.totalPoliciesFound = 0;

                    scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                        scope.totalPoliciesFound = totalCount;
                    });
                }
            };
        }]);