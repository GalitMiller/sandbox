angular.module("bricata.ui.policyapply")
    .directive("policySelect", [
        function () {

            return {
                restrict: 'E',
                templateUrl: 'modules/policyapply/views/policy-select.html',
                controller: 'PolicySelectionController'
            };
        }]);