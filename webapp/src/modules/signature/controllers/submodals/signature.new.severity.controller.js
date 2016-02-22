angular.module('bricata.ui.signature')
    .controller('SignatureNewSeverityController',
    ['$scope', '$modalInstance', '$rootScope', 'CommonModalService', 'CommonErrorMessageService',
        'cancelCallback', 'submitCallback', 'existingSeverities', 'SignatureDataService',
        function($scope, $modalInstance, $rootScope, CommonModalService, CommonErrorMessageService,
                 cancelCallback, submitCallback, existingSeverities, SignatureDataService) {

            $scope.isDataLoading = false;

            $scope.model = {
                data: {
                    name: "",
                    weight: null,
                    bg_color: "#d9534f"
                },
                validation: {
                    name: false,
                    priority: false,
                    bgClr: true
                }
            };

            $modalInstance.opened.then(function() {
                $rootScope.$broadcast('disable.validation');
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

            $scope.closeCategoryModal = function () {
                $rootScope.$broadcast('enable.validation');
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                cancelCallback();
            };

            $scope.isFormValid = function() {
                return $scope.model.validation.name && $scope.model.validation.priority &&
                    $scope.model.validation.bgClr;
            };

            $scope.saveSignatureSeverity = function() {
                if (!$scope.isFormValid()) {
                    $rootScope.$broadcast('run.validation', {group: 'signatureSeverityValidation'});
                    return;
                }

                var isUnique = true;
                var severity;
                for (var i = 0; i < existingSeverities.length; i++) {
                    severity = existingSeverities[i];

                    if (severity.name === $scope.model.data.name) {
                        isUnique = false;
                        break;
                    }
                }

                if (!isUnique) {
                    CommonErrorMessageService.showErrorMessage("validationErrors.signatureSeverityNameNotUnique", null,
                        "errors.formDataErrorCommonTitle");
                    return;
                }

                $scope.isDataLoading = true;
                SignatureDataService.createSeverity($scope.model.data).then(function success(data) {
                    $rootScope.$broadcast('enable.validation');
                    $modalInstance.close();
                    CommonModalService.unbindRepositionOnResize();

                    submitCallback(data);
                }, function(reason) {
                    $scope.isDataLoading = false;
                    CommonErrorMessageService.showErrorMessage("errors.createSeverityError", reason);
                });
            };

            $scope.$on('input.text.validation.processed', function(event, data) {
                if (angular.isDefined(data) && angular.isDefined(data.name)) {
                    switch (data.name) {
                        case 'signatureSeverityName':
                            $scope.model.validation.name = data.isValid;
                            break;
                        case 'signatureSeverityPriority':
                            $scope.model.validation.priority = data.isValid;
                            break;
                        case 'signatureSeverityBgColor':
                            $scope.model.validation.bgClr = data.isValid;
                            break;
                    }
                }
            });
        }]);
