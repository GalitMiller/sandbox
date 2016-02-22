angular.module('bricata.ui.policyapply')
    .controller('DifferenceManagementController',
    ['$scope', '$timeout', 'PolicyApplyDataService',
        function($scope, $timeout, PolicyApplyDataService) {
            $scope.isDifferencesPresent = false;

            $scope.setUpDifferences = function(){
                var differenceArr = PolicyApplyDataService.extractNonCommonPolicies($scope.model.mergedRows);
                $scope.isDifferencesPresent = false;

                if (differenceArr.length > 0) {
                    var i;
                    $scope.model.differences = angular.copy(differenceArr);
                    angular.forEach($scope.model.differences, function (sensorInterfaceRow) {
                        angular.forEach(sensorInterfaceRow.diff, function (policyObj) {
                            policyObj.isIncluded = true;
                            for (i = 0; i < $scope.model.conflictingPolicies.length; i++) {
                                if ($scope.model.conflictingPolicies[i].policy.id === policyObj.policy.id) {
                                    policyObj.isConflicting = true;
                                    break;
                                }
                            }
                        });
                        sensorInterfaceRow.diff.sort(function (a, b) {
                            if (a.policy.name > b.policy.name) {
                                return 1;
                            }
                            if (a.policy.name < b.policy.name) {
                                return -1;
                            }
                            return 0;
                        });
                    });

                    $scope.isDifferencesPresent = true;

                    $timeout(function(){
                        $scope.$broadcast('content.changed');
                    }, 300, false);
                }
            };

            $scope.submitDifferences = function(){
                var excludedListObj = {length: 0};
                var rowExclusion;
                var rowExclusionNum;
                var changedRows;
                var changedNum;
                var changedInterfaces = {};
                angular.forEach($scope.model.differences, function (sensorInterfaceRow) {
                    rowExclusion = {};
                    rowExclusionNum = 0;
                    changedRows = {};
                    changedNum = 0;
                    angular.forEach(sensorInterfaceRow.diff, function (policyObj) {
                        if (!policyObj.isIncluded) {
                            rowExclusion[policyObj.policy.id] = true;
                            rowExclusionNum++;
                        } else {
                            changedRows[policyObj.policy.id]= policyObj;
                            changedNum++;
                        }
                    });

                    if (rowExclusionNum > 0) {
                        excludedListObj[sensorInterfaceRow.interface.id] = rowExclusion;
                        excludedListObj.length += 1;
                    }

                    if (changedNum > 0) {
                        changedInterfaces[sensorInterfaceRow.interface.id] = changedRows;
                    }
                });

                $scope.processDiffManagementResult({
                    exclusion: excludedListObj,
                    change: changedInterfaces
                });
            };

        }]);
