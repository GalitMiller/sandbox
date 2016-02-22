angular.module("bricata.ui.sensors")
    .directive("inactiveSensorsSystemNotification",
    ["$i18next", "CommonNavigationService", "SensorsDataService",
        function($i18next, CommonNavigationService, SensorsDataService) {
            return {
                restrict: 'E',
                templateUrl: 'modules/sensors/views/inactive-sensors-notification.html',
                link: function(scope) {
                    scope.showInactiveSensorsNotification = false;
                    scope.displayNotification = function(inactiveSensorsCount) {
                        scope.msg = $i18next('inactiveSensorGrid.notificationMsg',
                            { postProcess: 'count', count: inactiveSensorsCount });
                        scope.showInactiveSensorsNotification = true;
                    };

                    scope.loadInactiveSensors = function() {
                        CommonNavigationService.navigateToInactiveSensorsGridPage();
                    };

                    SensorsDataService.getInactiveSensorsCount().then(function(data) {
                        if (data.result > 0) {
                            scope.displayNotification(data.result);
                        }
                    });
                }
            };
        }]);