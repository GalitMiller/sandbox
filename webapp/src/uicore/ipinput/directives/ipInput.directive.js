angular.module("bricata.uicore.ipinput")
    .directive("ipInput", [
        function() {
            return {
                restrict: 'E',
                templateUrl: 'uicore/ipinput/views/ipinput.html',
                controller: 'ipInputController',
                scope: {
                    selectedIpAddress: "=",
                    selectedPort: "=",
                    topValidationResultName: "@",
                    validationGroup: "@"
                }
        };
    }]);