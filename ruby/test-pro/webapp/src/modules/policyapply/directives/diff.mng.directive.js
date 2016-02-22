angular.module("bricata.ui.policyapply")
    .directive("manageDifferences", [
        function () {

            return {
                restrict: 'E',
                templateUrl: 'modules/policyapply/views/apply-diff-mng.html',
                controller: 'DifferenceManagementController'
            };
        }]);