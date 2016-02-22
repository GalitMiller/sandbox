angular.module('bricata.ui.referencetype')
    .controller('CreateReferenceTypeController',
    ['$scope', '$rootScope', '$i18next',
        'CommonNavigationService', 'BroadcastService', 'GridActionsHelper', 'gridStandardActions',
        'ValidationService', 'CommonErrorMessageService', 'ReferenceTypeDataService', 'SignatureDataService',
        function($scope, $rootScope, $i18next,
                 CommonNavigationService, BroadcastService, GridActionsHelper, gridStandardActions,
                 ValidationService, CommonErrorMessageService, ReferenceTypeDataService, SignatureDataService) {

            $scope.pageTitleI18N = 'createReferenceType.mainTitle';
            $scope.btnTitleI18N = 'generalElements.create';

            $scope.states = {
                isEditMode: false,
                isDataSendingInProgress: false
            };

            $scope.formData = {
                data: {
                    name: '',
                    url_prefix: ''
                },
                validation: {
                    name: false,
                    urlPrefix: false
                }
            };

            $scope.$on('input.text.validation.processed', function(event, data) {
                switch (data.name) {
                    case 'referenceNameValidation':
                        $scope.formData.validation.name = data.isValid;
                        break;
                    case 'referenceUrlValidation':
                        $scope.formData.validation.urlPrefix = data.isValid;
                        break;
                }
            });

            $scope.submitReferenceType = function() {
                if (!$scope.formData.validation.name || !$scope.formData.validation.urlPrefix) {
                    $rootScope.$broadcast('run.validation');
                } else {
                    $scope.createEditReferenceType();
                }
            };

            $scope.processEditReferenceTypeAction = function() {
                var editReferenceData = GridActionsHelper.getGridEditData();
                if (angular.isDefined(editReferenceData)) {
                    $scope.states.isEditMode = true;

                    $scope.pageTitleI18N = 'createReferenceType.editTitle';
                    $scope.btnTitleI18N = 'generalElements.save';
                    $scope.formData.data = {
                        id: editReferenceData.id,
                        name: editReferenceData.name,
                        url_prefix: editReferenceData.url_prefix
                    };

                    GridActionsHelper.consumeGridEditData();
                }
            };

            $scope.createEditReferenceType = function() {
                $scope.states.isDataSendingInProgress = true;

                ValidationService.ensureUnique(SignatureDataService.getReferenceTypes(),
                    $scope.formData.data, $scope.handleReferenceTypeNameValidationResult);
            };

            $scope.handleReferenceTypeNameValidationResult = function(isUnique, referenceTypeObject) {
                if (isUnique) {
                    if ($scope.states.isEditMode) {
                        ReferenceTypeDataService.editReferenceType(referenceTypeObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    } else {
                        ReferenceTypeDataService.createNewReferenceType(referenceTypeObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    }
                } else {
                    $scope.states.isDataSendingInProgress = false;
                    CommonErrorMessageService.showErrorMessage("validationErrors.referenceTypeNameNotUnique", null,
                        "errors.formDataErrorCommonTitle");
                }
            };

            $scope.successHandler = function(createdReferenceType) {
                CommonNavigationService.navigateToReferenceTypeGridPage();
                BroadcastService.changeTopLevelMessage({
                    item: createdReferenceType,
                    id: createdReferenceType.id,
                    action: $scope.states.isEditMode ? gridStandardActions.edit : gridStandardActions.create
                });
            };

            $scope.errorHandler = function(reason) {
                $scope.states.isDataSendingInProgress = false;
                var error = $scope.states.isEditMode ?
                    "errors.editReferenceError" : "errors.createReferenceError";
                CommonErrorMessageService.showErrorMessage(error, reason);
            };

            $scope.cancelWizard = function() {
                CommonNavigationService.navigateToReferenceTypeGridPage();
            };

            $scope.processEditReferenceTypeAction();

        }]);
