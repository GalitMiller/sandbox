angular.module("bricata.ui.policyapply")
    .directive("applyPolicy", [
    function () {
        return {
            restrict: 'E',
            templateUrl: 'modules/policyapply/views/apply-policy-modal.html'
        };
    }]);
