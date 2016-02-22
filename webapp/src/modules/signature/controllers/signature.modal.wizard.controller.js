angular.module('bricata.ui.signature')
    .controller('NewSignatureModalController',
    ['$scope', '$modalInstance', '$rootScope',
        'GridActionsHelper', 'CommonNavigationService', 'BricataUris',
        'CommonModalService', 'categoryId',
        'SignatureWizardService', 'ConfigurationService', 'CommonErrorMessageService',
        function($scope, $modalInstance, $rootScope,
                 GridActionsHelper, CommonNavigationService, BricataUris,
                 CommonModalService, categoryId,
                 SignatureWizardService, ConfigurationService, CommonErrorMessageService) {

            $scope.helpLinks = ConfigurationService.getSignatureHelpLinks();

            $scope.states = {
                isSubModalShown: false,
                isSignatureCategorySelectionDisabled: false
            };

            $scope.allowedSteps = {
                first: true,
                second: false,
                third: false,
                final: false
            };

            $scope.currentStep = {
                first: true,
                second: false,
                third: false
            };

            $scope.addNewSignatureModel = SignatureWizardService.initializeModel(categoryId);

            if (CommonNavigationService.isThisCurrentLocation(BricataUris.pages.signatureCategoriesPage)){
                $scope.states.isSignatureCategorySelectionDisabled = true;
            }

            var unbindIpValidationListener = $scope.$on('ip.input.validation.processed', function(event, data) {
                SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                $scope.processValidationResult();
            });

            var unbindInputValidationListener = $scope.$on('input.text.validation.processed', function(event, data) {
                SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                $scope.processValidationResult();
            });


            var unbindReferenceValidationListener =
                $scope.$on('reference.input.validation.processed', function(event, data) {
                    data.name = 'third_isReferenceValid';
                    SignatureWizardService.processValidationResults($scope.addNewSignatureModel.validation, data);

                    $scope.processValidationResult();
                });


            $scope.processValidationResult = function() {
                $scope.allowedSteps.second =
                    SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.first);

                $scope.allowedSteps.third = $scope.allowedSteps.second &&
                    SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.second);

                $scope.allowedSteps.final =
                    SignatureWizardService.isStepValid($scope.addNewSignatureModel.validation.third);
            };


            // Changing form switch states - going to next steps
            $scope.addNewSignatureModel.goToRulesInformation = function() {
                if ($scope.allowedSteps.first) {
                    $scope.currentStep.first = true;
                    $scope.currentStep.second = $scope.currentStep.third = false;
                }
            };
            $scope.addNewSignatureModel.goToSignatureInformation = function() {
                $scope.processValidationResult();

                if (!$scope.allowedSteps.second) {
                    $rootScope.$broadcast('run.validation', {group: 'signatureRulesValidation'});
                    return;
                }

                $scope.currentStep.second = true;
                $scope.currentStep.first = $scope.currentStep.third = false;
            };
            $scope.addNewSignatureModel.goToMetaInformation = function() {
                $scope.processValidationResult();

                if (!$scope.allowedSteps.third) {
                    if ($scope.currentStep.first) {
                        $rootScope.$broadcast('run.validation', {group: 'signatureRulesValidation'});
                    }

                    if ($scope.currentStep.second) {
                        $rootScope.$broadcast('run.validation', {group: 'signatureEntityValidation'});
                    }

                    return;
                }

                $scope.currentStep.third = true;
                $scope.currentStep.first = $scope.currentStep.second = false;
            };

            $scope.closePreviewRuleModal = function () {
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
                $scope.$destroy();
            };

            $scope.subModalCancel = function() {
                $scope.states.isSubModalShown = false;
                CommonModalService.centerModal();
            };

            $scope.previewSubmit = function() {
                $scope.saveAndClose();
            };

            $scope.previewLoadFail = function(reason) {
                $scope.subModalCancel();

                CommonErrorMessageService.showErrorMessage("errors.previewSignatureError", reason);
            };

            $scope.createSignature = function() {
                $scope.processValidationResult();

                if (!$scope.allowedSteps.final) {
                    $rootScope.$broadcast('run.validation', {group: 'signatureMetaValidation'});

                    return;
                }


                if ($scope.addNewSignatureModel.previewSignaturesBeforeSavingCheckBox.checked === true) {
                    $scope.states.isSubModalShown = true;

                    SignatureWizardService.previewSignature($scope.addNewSignatureModel.data, $scope.subModalCancel,
                        $scope.previewSubmit, $scope.previewLoadFail);
                } else {
                    $scope.saveAndClose();
                }
            };

            $scope.saveAndClose = function() {
                SignatureWizardService.saveSignature($scope.addNewSignatureModel.data,
                    $scope.handleSuccess, $scope.handleError);
            };

            $scope.handleSuccess = function(newSignatureData) {
                    $rootScope.$emit('signature.select.refresh',
                        {id: newSignatureData.category.id, signature: newSignatureData});

                $modalInstance.close({
                    id: -1,
                    bulkChangeIds: [newSignatureData.category.id],
                    field: 'signatures_count',
                    value: newSignatureData.category.signatures_count
                });

                CommonModalService.unbindRepositionOnResize();
            };

            $scope.handleError = function(reason) {
                CommonErrorMessageService.showErrorMessage("errors.createSignatureError", reason);
            };

            $scope.openNewCategoryModal = function() {
                SignatureWizardService.openNewSignatureCategoryDialog($scope.subModalCancel,
                    $scope.newCategoryCreated, $scope.addNewSignatureModel.categories);

                $scope.states.isSubModalShown = true;
            };

            $scope.openNewSeverityModal = function() {
                SignatureWizardService.openNewSignatureSeverityDialog($scope.subModalCancel,
                    $scope.newSeverityCreated, $scope.addNewSignatureModel.values.severities);

                $scope.states.isSubModalShown = true;
            };

            $scope.newCategoryCreated = function(createdCategory) {
                $scope.subModalCancel();

                $scope.addNewSignatureModel.categories.unshift(createdCategory);
                $scope.addNewSignatureModel.data.categoryId = createdCategory.id;

                $rootScope.$emit('signature.select.refresh', {id: createdCategory.id});
            };

            $scope.newSeverityCreated = function(createdSeverity) {
                $scope.subModalCancel();

                $scope.addNewSignatureModel.values.severities.unshift(createdSeverity);
                $scope.addNewSignatureModel.data.severityId = createdSeverity.id;
            };

            $scope.handleClassTypeChange = function() {
                SignatureWizardService.syncSeverityWithClassTypeSelection(
                    $scope.addNewSignatureModel.data, $scope.addNewSignatureModel.values);
            };

            $scope.closeSignatureModal = function () {
                $rootScope.$emit('enable.validation');
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                $scope.$destroy();
            };

            $modalInstance.opened.then(function() {
                $rootScope.$emit('disable.validation');
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

            //cleaning resources
            var unbindDestroy = $scope.$on("$destroy", function() {
                unbindIpValidationListener();
                unbindInputValidationListener();
                unbindReferenceValidationListener();
                unbindDestroy();
            });

        }]);
