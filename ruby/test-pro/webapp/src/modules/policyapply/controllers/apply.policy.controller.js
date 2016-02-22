angular.module('bricata.ui.policyapply')
    .controller('ApplyPolicyController',
    ['$scope', '$modalInstance', '$rootScope', 'CommonModalService', 'PolicyDataService', 'SensorsDataService',
        'PolicyApplyDataService', 'ConfigurationService', 'CommonErrorMessageService', 'UserInfoService', '$q',
        'CommonProxyForRequests', 'CommonAlertMessageService',
    function($scope, $modalInstance, $rootScope, CommonModalService, PolicyDataService, SensorsDataService,
             PolicyApplyDataService, ConfigurationService, CommonErrorMessageService, UserInfoService, $q,
             CommonProxyForRequests, CommonAlertMessageService) {

        $scope.states = {
            isDataLoading: true,
            isSubModalShown: false,
            refreshPoliciesNeeded: true,
            refreshDifferencesNeeded: true
        };

        $scope.model = {
            applyForAll: false,
            isValid: false,
            validation: {
                sensors: false,
                policies: false
            },
            values: {
                policies: [],
                sensors: [],
                deployments: ConfigurationService.getPolicyDeploymentModes(),
                actions: ConfigurationService.getPolicyActions(),
                policyOptions: []
            },
            sensorInterfaces: [{
                sensor: {},
                interface: {},
                policies: []
            }],
            commonPolicies: [{
                policy: {},
                action: {}
            }],
            conflictingPolicies: [],
            loadingInterfacesAndApplications: {
                progress: 0
            },
            mergedRows: [],
            differences: []
        };

        $scope.currentStep = {
            first: true,
            second: false,
            third: false
        };

        $q.all([
            PolicyDataService.getPolicyNames(),
            SensorsDataService.getAllSensors()
        ]).then(function(data) {
            $scope.model.values.policies = data[0];
            $scope.model.values.sensors = data[1];

            if ($scope.model.values.policies.length === 0) {
                $scope.states.isSubModalShown = true;
                CommonAlertMessageService.showMessage("applyPolicyModal.applyPolicyTitle",
                    "applyPolicyModal.noPoliciesFoundError", "applyPolicyModal.noPoliciesFoundErrorDetail",
                    $scope.closeApplyPolicyModal);
            } else if ($scope.model.values.sensors.length === 0) {
                $scope.states.isSubModalShown = true;
                CommonAlertMessageService.showMessage("applyPolicyModal.applyPolicyTitle",
                    "applyPolicyModal.noSensorsFoundError", "applyPolicyModal.noSensorsFoundErrorDetail",
                    $scope.closeApplyPolicyModal);
            }

            $scope.states.isDataLoading = false;
            CommonModalService.centerModal();
        });

        $scope.goToSensorSelection = function(){
            $scope.currentStep = {
                first: true,
                second: false,
                third: false
            };
        };
        $scope.goToPolicySelection = function(){
            if (!$scope.states.refreshPoliciesNeeded) {
                $scope.currentStep = {
                    first: false,
                    second: true,
                    third: false
                };
                return;
            }
            if ($scope.model.validation.sensors) {
                $scope.model.loadingInterfacesAndApplications.progress = 0;
                $scope.states.isDataLoading = true;

                if ($scope.model.sensorInterfaces.length > 0 && !$scope.model.applyForAll) {
                    $scope.setPolicyApplicationInfoAndNavToPolicies(100);
                } else {
                    PolicyApplyDataService.setUpInterfacesForAllSensors($scope.model.sensorInterfaces,
                        $scope.model.values.sensors, 20, $scope.model.loadingInterfacesAndApplications).then(
                        function success(){
                            $scope.setPolicyApplicationInfoAndNavToPolicies(80);
                        },
                        function(){
                            $scope.states.isSubModalShown = true;
                            CommonAlertMessageService.showMessage("applyPolicyModal.applyPolicyTitle",
                                "applyPolicyModal.interfacesLoadError", "applyPolicyModal.interfacesLoadErrorDetail",
                                $scope.closeApplyPolicyModal);
                        });
                }

            } else {
                $rootScope.$broadcast('run.validation');
            }
        };

        $scope.goToDiffManagement = function(){
            if ($scope.states.refreshPoliciesNeeded) {
                $scope.goToPolicySelection();
                return;
            }

            if ($scope.model.validation.policies) {
                $scope.currentStep = {
                    first: false,
                    second: false,
                    third: true
                };

                if ($scope.states.refreshDifferencesNeeded) {
                    $scope.model.mergedRows = angular.copy($scope.model.sensorInterfaces);

                    PolicyApplyDataService.mergeCommonPoliciesIntoRows($scope.model.mergedRows,
                        $scope.model.commonPolicies);

                    $scope.setUpDifferences();
                    $scope.states.refreshDifferencesNeeded = false;
                }
            } else {
                $rootScope.$broadcast('run.validation');
            }
        };

        $scope.setPolicyApplicationInfoAndNavToPolicies = function(percentage){
            PolicyApplyDataService.loadAppliedPoliciesForSensors($scope.model.sensorInterfaces,
                $scope.model.values.policies, $scope.model.values.actions, percentage,
                $scope.model.loadingInterfacesAndApplications).then(function success(){

                    var intersection = PolicyApplyDataService.
                        findIntersectionAndConflictsOfAppliedPolicies($scope.model.sensorInterfaces);
                    $scope.model.commonPolicies = intersection.common;
                    $scope.model.conflictingPolicies = intersection.conflicts;

                    if ($scope.model.commonPolicies.length === 0){
                        $scope.model.commonPolicies.push({policy: {}, action: {}});
                    }

                    PolicyApplyDataService.removeCommonPoliciesFromRows($scope.model.sensorInterfaces,
                        $scope.model.commonPolicies);

                    $scope.model.values.policyOptions = PolicyApplyDataService.getNonConflictingPoliciesForSetUp(
                        $scope.model.values.policies, $scope.model.conflictingPolicies);

                    $scope.states.isDataLoading = false;
                    $scope.currentStep = {
                        first: false,
                        second: true,
                        third: false
                    };
                    $rootScope.$broadcast('run.validation');

                    $scope.states.refreshPoliciesNeeded = false;
                });
        };

        var unbindPoliciesSelectValidationListener = $scope.$on('policies.select.validation.processed',
            function(event, data) {
                $scope.model.validation.policies = data.isValid;

                $scope.checkValidationResult();
            });

        var unbindSensorsSelectValidationListener = $scope.$on('sensors.select.validation.processed',
            function(event, data) {
                $scope.model.validation.sensors = data.isValid;

                $scope.checkValidationResult();
            });

        $scope.checkValidationResult = function() {
            $scope.model.isValid = $scope.model.validation.policies && $scope.model.validation.sensors;
        };

        $scope.processDiffManagementResult = function(diffManagementRes){
            var excludedRulesObj = diffManagementRes.exclusion;
            $scope.states.isSubModalShown = false;
            $scope.states.isDataLoading = true;
            if (excludedRulesObj.length > 0) {
                PolicyApplyDataService.excludeUncheckedDiffFromMerged(excludedRulesObj, $scope.model.mergedRows);
            }

            PolicyApplyDataService.mergeManagedDifferences(diffManagementRes.change, $scope.model.mergedRows);

            if (!$scope.model.isValid) {
                $rootScope.$broadcast('run.validation');
                return;
            }

            $scope.processApply();
        };

        $scope.processApply = function(){
            var dataToSend = {
                applications: []
            };

            var singleApplicationObj = {
                interface_id: -1,
                policies: []
            };
            var applicationObj;
            var policyIds = [];

            angular.forEach($scope.model.mergedRows, function(sensorInterface) {
                applicationObj = angular.copy(singleApplicationObj);
                applicationObj.interface_id = sensorInterface.interface.id;

                angular.forEach(sensorInterface.policies, function(policyObj) {
                    applicationObj.policies.push({
                        policy_id: policyObj.policy.id,
                        action: policyObj.action.value
                    });

                    if (policyIds.indexOf(policyObj.policy.id) < 0) {
                        policyIds.push(policyObj.policy.id);
                    }
                });

                dataToSend.applications.push(applicationObj);
            });

            PolicyApplyDataService.applyPolicy(dataToSend).then(function success() {
                $modalInstance.close({
                    id: -1/*,
                    bulkChangeIds: policyIds,
                    field: 'last_applied_by',
                    value: {name: UserInfoService.getSavedUserName()}*/
                });
                CommonModalService.unbindRepositionOnResize();

                $scope.$destroy();
            }, function error(reason) {
                $scope.states.isDataLoading = false;
                CommonErrorMessageService.showErrorMessage("errors.applyPolicyError", reason);
            });
        };

        $scope.closeApplyPolicyModal = function () {
            $modalInstance.dismiss('cancel');
            CommonModalService.unbindRepositionOnResize();
            CommonProxyForRequests.cancelAllPendingRequests();
            $scope.$destroy();
        };

        $modalInstance.opened.then(function() {
            CommonModalService.centerModal();
            CommonModalService.bindRepositionOnResize();
        });

        //cleaning resources
        var unbindDestroy = $scope.$on("$destroy", function() {
            unbindPoliciesSelectValidationListener();
            unbindSensorsSelectValidationListener();
            unbindDestroy();
        });

    }]);
