angular.module('bricata.ui.signaturecategories')
    .controller('CreateSignatureCategoryController',
    ['$scope', '$rootScope', '$i18next',
        'CommonNavigationService', 'BroadcastService', 'GridActionsHelper', 'SignatureDataService',
        'ValidationService', 'CommonErrorMessageService', 'SignatureCategoriesDataService', 'gridStandardActions',
    function($scope, $rootScope, $i18next,
             CommonNavigationService, BroadcastService, GridActionsHelper, SignatureDataService,
             ValidationService, CommonErrorMessageService, SignatureCategoriesDataService, gridStandardActions) {

        $scope.pageTitleI18N = 'createSignatureCategory.mainTitle';
        $scope.btnTitleI18N = 'generalElements.create';

        $scope.states = {
            isEditMode: false,
            isSignatureCategoryDataSendingInProgress: false
        };

        $scope.formData = {
            data: {
              name: '',
              description: ''
            },
            validation: {
                name: false,
                description: false
            }
        };

        $scope.$on('input.text.validation.processed', function(event, data) {
            switch (data.name) {
                case 'signatureCategoryNameValidation':
                    $scope.formData.validation.name = data.isValid;
                    break;
                case 'signatureCategoryDescriptionValidation':
                    $scope.formData.validation.description = data.isValid;
                    break;
            }
        });

        $scope.submitSignatureCategory = function() {
            if (!$scope.formData.validation.name || !$scope.formData.validation.description) {
                $rootScope.$broadcast('run.validation');
            }
            else {
                $scope.createEditSignatureCategory();
            }
        };

        $scope.processEditSignatureCategoryAction = function() {
            var editSignatureCategoryData = GridActionsHelper.getGridEditData();
            if (angular.isDefined(editSignatureCategoryData)) {
                $scope.states.isEditMode = true;

                $scope.pageTitleI18N = 'createSignatureCategory.editTitle';
                $scope.btnTitleI18N = 'generalElements.save';
                $scope.formData.data = editSignatureCategoryData;

                GridActionsHelper.consumeGridEditData();
            }
        };

        $scope.createEditSignatureCategory = function() {
            $scope.states.isSignatureCategoryDataSendingInProgress = true;

            ValidationService.ensureUnique(SignatureDataService.getSignatureCategoriesLite(),
                $scope.formData.data, $scope.handleSignatureCategoryNameValidationResult);
        };

        $scope.handleSignatureCategoryNameValidationResult = function(isUnique, signatureCategoryObject) {
            if (isUnique) {
                if ($scope.states.isEditMode) {
                    SignatureCategoriesDataService.editSignatureCategory(signatureCategoryObject)
                    .then($scope.successHandler, $scope.errorHandler);
                } else {
                    SignatureCategoriesDataService.createNewSignatureCategory(signatureCategoryObject)
                        .then($scope.successHandler, $scope.errorHandler);
                }
            } else {
                $scope.states.isSignatureCategoryDataSendingInProgress = false;
                CommonErrorMessageService.showErrorMessage("validationErrors.signatureCategoryNameNotUnique", null,
                    "errors.formDataErrorCommonTitle");
            }
        };

        $scope.successHandler = function(createdSignatureCategory) {
            CommonNavigationService.navigateToSignatureCategoriesGridPage();
            BroadcastService.changeTopLevelMessage({
                item: createdSignatureCategory,
                id: createdSignatureCategory.id,
                action: $scope.states.isEditMode ? gridStandardActions.edit : gridStandardActions.create
            });
        };

        $scope.errorHandler = function(reason) {
            $scope.states.isSignatureCategoryDataSendingInProgress = false;
            var error = $scope.states.isEditMode ?
                "errors.editSignatureCategoryError" : "errors.createSignatureCategoryError";
            CommonErrorMessageService.showErrorMessage(error, reason);
        };

        $scope.cancelWizard = function() {
            CommonNavigationService.navigateToSignatureCategoriesGridPage();
        };

        $scope.processEditSignatureCategoryAction();

    }]);
