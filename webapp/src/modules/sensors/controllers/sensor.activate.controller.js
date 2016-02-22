angular.module('bricata.ui.sensors')
    .controller('ActivateSensorController',
    ['$scope', '$modalInstance', '$rootScope', 'CommonModalService', 'SensorsDataService',
        'CommonErrorMessageService', 'inactiveSensor',
        function($scope, $modalInstance, $rootScope, CommonModalService, SensorsDataService,
                 CommonErrorMessageService, inactiveSensor) {

            $scope.testingSshConnection = false;

            $scope.formData = {};

            $scope.formData.activationData = {
                sensorId: inactiveSensor.id,
                hostname: inactiveSensor.hostname
                /*username: '',
                password: ''*/
            };

            $scope.formData.validation = {
                host: inactiveSensor.hostname !== ''
                /*name: false,
                psw: false*/
            };

            $scope.formData.isValid = false;

            $scope.currentSensorName = inactiveSensor.name;

            $scope.$on('input.text.validation.processed', function(event, data) {
                switch (data.name) {
                    case 'sensorHostValidation':
                        $scope.formData.validation.host = data.isValid;
                        break;
                    /*case 'sensorUserNameValidation':
                        $scope.formData.validation.name = data.isValid;
                        break;
                    case 'sensorPasswordValidation':
                        $scope.formData.validation.psw = data.isValid;
                        break;*/
                }

                $scope.checkValidationResult();
            });

            $scope.checkValidationResult = function() {
                $scope.formData.isValid = $scope.formData.validation.host;/* && $scope.formData.validation.name &&
                    $scope.formData.validation.psw;*/
            };

            $scope.performActivation = function() {
                $scope.checkValidationResult();
                if (!$scope.formData.isValid) {
                    $rootScope.$broadcast('run.validation');
                    return;
                }

                $scope.testingSshConnection = true;

                SensorsDataService.activateSensor($scope.formData.activationData.sensorId,
                    $scope.formData.activationData).then(function success(activationData) {
                        if (activationData.succeed) {
                            $modalInstance.close([{
                                item: {},
                                id: -1
                            }]);
                            CommonModalService.unbindRepositionOnResize();
                        } else {
                            activationData.data = {
                                message: activationData.message
                            };
                            $scope.handleActivationError(activationData);
                        }

                    }, function error(reason) {
                        $scope.handleActivationError(reason);
                    });
            };

            $scope.handleActivationError = function(reason) {
                $scope.testingSshConnection = false;
                CommonErrorMessageService.showErrorMessage("errors.sensorActivationError", reason);
            };

            $scope.closeSensorActivateModal = function () {
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                $scope.$destroy();
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

            $scope.handleKeyPress = function(event) {
                if(event.which === 13) {
                    $scope.performActivation();
                }
            };

        }]);
