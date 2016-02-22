angular.module("bricata.ui.policyapply")
    .directive("sensorSelect", [
        function () {

            return {
                restrict: 'E',
                templateUrl: 'modules/policyapply/views/sensor-select.html',
                controller: 'SensorSelectionController'
            };
        }]);