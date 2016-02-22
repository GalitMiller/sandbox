angular.module('bricata.ui.signatureclasstypes')
    .controller('CreateSignatureClassTypeController',
    ['$scope', '$rootScope', '$i18next',
        'CommonNavigationService', 'BroadcastService', 'GridActionsHelper',
        'ValidationService', 'CommonErrorMessageService', 'SignatureClassTypesDataService', 'gridStandardActions',
        function ($scope, $rootScope, $i18next,
                  CommonNavigationService, BroadcastService, GridActionsHelper,
                  ValidationService, CommonErrorMessageService, SignatureClassTypesDataService, gridStandardActions) {

            $scope.pageTitleI18N = 'createSignatureClassType.mainTitle';
            $scope.btnTitleI18N = 'generalElements.create';

            $scope.states = {
                isEditMode: false,
                isSignatureClassTypeDataSendingInProgress: false
            };

            $scope.formData = {
                data: {
                    name: '',
                    short_name: '',
                    priority: ''
                },
                validation: {
                    name: false,
                    short_name: false,
                    priority: false
                }
            };

            $scope.$on('input.text.validation.processed', function (event, data) {
                switch (data.name) {
                    case 'signatureClassTypeNameValidation':
                        $scope.formData.validation.name = data.isValid;
                        break;
                    case 'signatureClassTypeShortNameValidation':
                        $scope.formData.validation.shortName = data.isValid;
                        break;
                    case 'signatureClassTypePriorityValidation':
                        $scope.formData.validation.priority = data.isValid;
                        break;
                }
            });

            $scope.submitSignatureClassType = function () {
                if (!$scope.formData.validation.name ||
                    !$scope.formData.validation.shortName ||
                    !$scope.formData.validation.priority) {
                    $rootScope.$broadcast('run.validation');
                }
                else {
                    $scope.createEditSignatureClassType();
                }
            };

            $scope.processEditSignatureClassTypeAction = function () {
                var editSignatureClassTypeData = GridActionsHelper.getGridEditData();
                if (angular.isDefined(editSignatureClassTypeData)) {
                    $scope.states.isEditMode = true;

                    $scope.pageTitleI18N = 'createSignatureClassType.editTitle';
                    $scope.btnTitleI18N = 'generalElements.save';
                    $scope.formData.data = {
                        id: editSignatureClassTypeData.id,
                        name: editSignatureClassTypeData.name,
                        short_name: editSignatureClassTypeData.short_name,
                        priority: editSignatureClassTypeData.priority
                    };

                    GridActionsHelper.consumeGridEditData();
                }
            };

            $scope.createEditSignatureClassType = function () {
                $scope.states.isSignatureClassTypeDataSendingInProgress = true;

                ValidationService.ensureUnique(SignatureClassTypesDataService.getSignatureClassTypeItem(),
                    $scope.formData.data, $scope.handleSignatureClassTypeValidationResult);
            };

            $scope.handleSignatureClassTypeValidationResult = function (isUnique, signatureClassTypeObject) {
                if (isUnique) {
                    if ($scope.states.isEditMode) {
                        SignatureClassTypesDataService.editSignatureClassTypeItem(signatureClassTypeObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    } else {
                        SignatureClassTypesDataService.createNewSignatureClassTypeItem(signatureClassTypeObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    }
                } else {
                    $scope.states.isSignatureClassTypeDataSendingInProgress = false;
                    CommonErrorMessageService.showErrorMessage("validationErrors.signatureClassTypeNameNotUnique", null,
                        "errors.formDataErrorCommonTitle");
                }
            };

            $scope.successHandler = function (editSignatureClassType) {
                CommonNavigationService.navigateToSignatureClassTypePage();
                BroadcastService.changeTopLevelMessage({
                    item: editSignatureClassType,
                    id: editSignatureClassType.id,
                    action: $scope.states.isEditMode ? gridStandardActions.edit : gridStandardActions.create
                });
            };

            $scope.errorHandler = function (reason) {
                $scope.states.isSignatureClassTypeDataSendingInProgress = false;
                var error = $scope.states.isEditMode ?
                    "errors.editSignatureClassTypeError" : "errors.createSignatureClassTypeError";
                CommonErrorMessageService.showErrorMessage(error, reason);
            };

            $scope.cancelWizard = function () {
                CommonNavigationService.navigateToSignatureClassTypePage();
            };

            $scope.processEditSignatureClassTypeAction();

        }]);