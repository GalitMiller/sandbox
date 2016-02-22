
angular.module('bricata.ui.signature')
    .controller('SignatureWizardController',
    ['$scope', '$rootScope', 'SignatureWizardService', 'ConfigurationService', 'SignatureDataService',
        'CommonNavigationService', 'CommonErrorMessageService', 'GridActionsHelper', 'BroadcastService',
        'gridStandardActions', '$i18next',
        function($scope, $rootScope, SignatureWizardService, ConfigurationService, SignatureDataService,
                 CommonNavigationService, CommonErrorMessageService, GridActionsHelper, BroadcastService,
                 gridStandardActions, $i18next) {

            $scope.helpLinks = ConfigurationService.getSignatureHelpLinks();
            $scope.isDataValid = false;
            $scope.isEditMode = false;
            $scope.isLoadingData = true;

            $scope.labels = {
                title: 'createSignature.createNewSignature',
                submitBtnLbl: 'generalElements.create'
            };

            $scope.$on('ip.input.validation.processed', function(event, data) {
                SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                $scope.processValidationResult();
            });

            $scope.$on('input.text.validation.processed', function(event, data) {
                SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                $scope.processValidationResult();
            });


            $scope.$on('reference.input.validation.processed', function(event, data) {
                data.name = 'third_isReferenceValid';
                SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                $scope.processValidationResult();
            });


            $scope.processValidationResult = function() {
                $scope.isDataValid =
                        SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.first) &&
                    SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.second) &&
                    SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.third);
            };

            $scope.cancelWizard = function() {
                CommonNavigationService.navigateToSignaturesGridPage();
            };

            $scope.createSignature = function() {
                $scope.processValidationResult();

                if (!$scope.isDataValid) {
                    $rootScope.$broadcast('run.validation');

                    return;
                }

                if ($scope.addNewSignatureModel.previewSignaturesBeforeSavingCheckBox.checked === true) {
                    SignatureWizardService.previewSignature($scope.addNewSignatureModel.data, null,
                        $scope.previewSubmit, $scope.previewLoadFail);
                } else {
                    $scope.saveAndClose();
                }
            };

            $scope.previewSubmit = function() {
                $scope.saveAndClose();
            };

            $scope.previewLoadFail = function(reason) {
                CommonErrorMessageService.showErrorMessage("errors.previewSignatureError", reason);
            };

            $scope.saveAndClose = function() {
                if ($scope.isEditMode) {
                    SignatureWizardService.editSignature($scope.addNewSignatureModel.data,
                        $scope.handleSuccess, $scope.handleError);
                } else {
                    SignatureWizardService.saveSignature($scope.addNewSignatureModel.data,
                        $scope.handleSuccess, $scope.handleError);
                }
            };

            $scope.handleSuccess = function(newSignatureData) {
                CommonNavigationService.navigateToSignaturesGridPage();
                BroadcastService.changeTopLevelMessage({
                    item: newSignatureData,
                    id: newSignatureData.id,
                    action: $scope.isEditMode ? gridStandardActions.edit : gridStandardActions.create
                });
            };

            $scope.handleError = function(reason) {
                CommonErrorMessageService.showErrorMessage(
                    $scope.isEditMode ? "errors.editSignatureError" : "errors.createSignatureError",
                    reason);
            };

            $scope.openNewCategoryModal = function() {
                SignatureWizardService.openNewSignatureCategoryDialog(null,
                    $scope.newCategoryCreated, $scope.addNewSignatureModel.categories);
            };

            $scope.openNewSeverityModal = function() {
                SignatureWizardService.openNewSignatureSeverityDialog(null,
                    $scope.newSeverityCreated, $scope.addNewSignatureModel.values.severities);
            };

            $scope.newCategoryCreated = function(createdCategory) {
                $scope.addNewSignatureModel.categories.unshift(createdCategory);
                $scope.addNewSignatureModel.data.categoryId = createdCategory.id;
            };

            $scope.newSeverityCreated = function(createdSeverity) {
                $scope.addNewSignatureModel.values.severities.unshift(createdSeverity);
                $scope.addNewSignatureModel.data.severityId = createdSeverity.id;
            };

            $scope.processCloneSignatureAction = function() {
                var cloneSignatureData = GridActionsHelper.getGridCloneData();
                if (angular.isDefined(cloneSignatureData)) {
                    $scope.isLoadingData = true;
                    $scope.labels = {
                        title: 'createSignature.cloneTitle',
                        submitBtnLbl: 'generalElements.clone'
                    };

                    GridActionsHelper.consumeGridCloneData();

                    SignatureDataService.getSignature(cloneSignatureData.id).then(function success(cloneData) {
                        SignatureWizardService.convertEditDataToModel(cloneData, $scope.addNewSignatureModel.data,
                            true);

                        $scope.addNewSignatureModel.data.name = $i18next('createSignature.cloneSignaturePrefixAndName',
                            { postProcess: 'sprintf', sprintf: [cloneData.name] });

                        $scope.isLoadingData = false;
                    });
                }
            };

            $scope.processEditSignatureAction = function() {
                var editSignatureData = GridActionsHelper.getGridEditData();
                if (editSignatureData) {
                    $scope.isLoadingData = true;
                    $scope.isEditMode = true;
                    $scope.labels = {
                        title: 'createSignature.editTitle',
                        submitBtnLbl: 'generalElements.save'
                    };

                    GridActionsHelper.consumeGridEditData();

                    SignatureDataService.getSignature(editSignatureData.id).then(function success(editData) {
                        SignatureWizardService.convertEditDataToModel(editData, $scope.addNewSignatureModel.data);

                        $scope.isLoadingData = false;
                    });
                }
            };

            $scope.handleClassTypeChange = function() {
                SignatureWizardService.syncSeverityWithClassTypeSelection(
                    $scope.addNewSignatureModel.data, $scope.addNewSignatureModel.values);
            };

            $scope.addNewSignatureModel = SignatureWizardService.initializeModel(null, function() {
                $scope.isLoadingData = false;
                $scope.processCloneSignatureAction();
                $scope.processEditSignatureAction();
            });
        }]);
