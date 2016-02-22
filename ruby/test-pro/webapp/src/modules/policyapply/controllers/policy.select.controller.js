angular.module('bricata.ui.policyapply')
    .controller('PolicySelectionController', ['$scope',
        function($scope) {

            $scope.duplicatePolicyFound = false;
            $scope.isApplyPolicyFormInvalid = true;

            $scope.policiesSelectError = '';

            $scope.policiesSelectErrorUpdated = function(newMsg){
                $scope.policiesSelectError = newMsg;
            };

            $scope.addPolicyRow = function () {
                $scope.states.refreshDifferencesNeeded = true;

                $scope.model.commonPolicies.push({policy: {}, action: {}});
                $scope.$broadcast('content.changed');
                $scope.$broadcast('scrollable.scroll.bottom');
            };

            $scope.removePolicyRow = function (index) {
                $scope.states.refreshDifferencesNeeded = true;

                $scope.model.commonPolicies.splice(index, 1);
                $scope.$broadcast('content.changed');
            };

            $scope.handlePolicyChange = function(){
                $scope.states.refreshDifferencesNeeded = true;
            };

            $scope.handleConflictsShown = function() {
                $scope.$broadcast('content.changed');
            };

        }]);
