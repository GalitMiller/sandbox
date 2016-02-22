angular.module("bricata.ui.policy")
    .directive("policyHeaderNavigation", [ "CommonNavigationService",
    function (CommonNavigationService) {

        return {
            restrict: 'E',
            templateUrl: 'modules/policy/views/policyHeaderNav.html',
            link: function(scope) {
                scope.totalPoliciesFound = 0;

                scope.openApplyPolicyDialog = function() {
                    var eventData = {
                        actionName: "policyApply",
                        actionType: "modal",
                        data: []
                    };

                    scope.$broadcast('grid.header.invoke.row.action', eventData);
                };

                scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                    scope.totalPoliciesFound = totalCount;
                });

                scope.navToWizardPage = function() {
                    CommonNavigationService.navigateToPolicyWizardPage();
                };
            }
        };
    }]);