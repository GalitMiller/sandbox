angular.module('bricata.ui.policyapply')
    .controller('SensorSelectionController', ['$scope', 'SensorsDataService', 'CommonAlertMessageService',
        function($scope, SensorsDataService, CommonAlertMessageService) {
            $scope.priorSelection = [];

            $scope.duplicateSensorFound = false;

            $scope.sensorSelectError = '';
            $scope.sensorsSelectErrorUpdated = function(newMsg){
                $scope.sensorSelectError = newMsg;
            };

            $scope.addSensorRow = function () {
                $scope.states.refreshPoliciesNeeded = true;
                $scope.states.refreshDifferencesNeeded = true;

                $scope.model.sensorInterfaces.push({sensor: {}, interface: {}, policies: []});
                $scope.$broadcast('content.changed');
                $scope.$broadcast('scrollable.scroll.bottom');
            };

            $scope.removeSensorRow = function (index) {
                $scope.states.refreshPoliciesNeeded = true;
                $scope.states.refreshDifferencesNeeded = true;

                $scope.model.sensorInterfaces.splice(index, 1);
                $scope.$broadcast('content.changed');
            };

            $scope.clearSelectedInterface = function(row){
                row.interface = {};
            };

            $scope.loadInterfacesForSensor = function(sensor) {
                $scope.states.refreshPoliciesNeeded = true;
                $scope.states.refreshDifferencesNeeded = true;

                $scope.states.isDataLoading = true;
                SensorsDataService.getSensorInterfaces(sensor.id).then(function success(data) {
                    $scope.states.isDataLoading = false;

                    sensor.interfaces = data;
                },
                function error(){
                    $scope.states.isSubModalShown = true;
                    CommonAlertMessageService.showMessage("applyPolicyModal.applyPolicyTitle",
                        "applyPolicyModal.interfacesLoadError", "applyPolicyModal.interfacesLoadErrorDetail",
                        $scope.closeApplyPolicyModal);
                });
            };

            $scope.handleInterfacesChange = function(){
                $scope.states.refreshPoliciesNeeded = true;
                $scope.states.refreshDifferencesNeeded = true;
            };

            $scope.applyForOptionChange = function(){
                $scope.handleInterfacesChange();

                if ($scope.model.applyForAll) {
                    $scope.priorSelection = angular.copy($scope.model.sensorInterfaces);
                    $scope.model.sensorInterfaces = [];
                } else {
                    if ($scope.priorSelection.length > 0) {
                        $scope.model.sensorInterfaces = angular.copy($scope.priorSelection);
                    } else {
                        $scope.model.sensorInterfaces = [{
                            sensor: {},
                            interface: {},
                            policies: []
                        }];
                    }
                }

                $scope.model.commonPolicies = [{
                    policy: {},
                    action: {}
                }];

                $scope.model.validation.sensors = $scope.model.applyForAll;
            };
        }]);
