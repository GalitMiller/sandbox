angular.module('bricata.ui.policy')
    .controller('CreatePolicyController',
    ['$scope', '$rootScope', '$i18next', 'CommonModalService', 'CommonNavigationService', 'BroadcastService',
        'PolicyDataService', 'ConfigurationService', 'CommonErrorMessageService', 'ValidationService',
        'GridActionsHelper', 'gridStandardActions',
    function($scope, $rootScope, $i18next, CommonModalService, CommonNavigationService, BroadcastService,
             PolicyDataService, ConfigurationService, CommonErrorMessageService, ValidationService, GridActionsHelper,
             gridStandardActions) {

        $scope.pageTitleI18N = 'createPolicy.mainTitle';
        $scope.btnTitleI18N = 'generalElements.create';

        $scope.preselectedData = [];

        $scope.states = {
            isEditMode: false,
            isCloneMode: false,
            isPolicyDataSendingInProgress: false,
            signatureSelectionEnabled: false,
            signatureSelectionMode: ''
        };

        $scope.policyData = {
            id: -1,
            policyName: '',
            description: '',
            type: undefined,
            selectedSignatures: []
        };

        $scope.previewBeforeSavingCheckboxModel = {
            checked : false
        };

        $scope.formData = {
            validation: {
                name: false,
                description: false,
                category: false,
                signatures: false
            },

            isValid: false
        };

        $scope.policyTypeList = ConfigurationService.getPolicyTypes();
        $scope._policyType = '';

        $scope.$on('input.text.validation.processed', function(event, data) {
            switch (data.name) {
                case 'policyNameValidation':
                    $scope.formData.validation.name = data.isValid;
                    break;
                case 'policyDescriptionValidation':
                    $scope.formData.validation.description = data.isValid;
                    break;
                case 'policyCategoryValidation':
                    $scope.formData.validation.category = data.isValid;
                    break;
            }

            $scope.checkValidationResult();
        });

        $scope.$on('signature.select.validation.processed', function(event, data) {
            $scope.formData.validation.signatures = data.isValid;

            $scope.checkValidationResult();
        });

        $scope.checkValidationResult = function() {
            if ($scope.states.signatureSelectionEnabled) {
                $scope.formData.isValid = $scope.formData.validation.name && $scope.formData.validation.description &&
                    $scope.formData.validation.category &&
                    ($scope.formData.validation.signatures || $scope.policyData.selectedSignatures.length > 0);
            } else {
                $scope.formData.isValid = $scope.formData.validation.name && $scope.formData.validation.description &&
                    $scope.formData.validation.category;
            }
        };

        // Submit New Policy Form
        $scope.submitPolicy = function() {
            $scope.checkValidationResult();
            if (!$scope.formData.isValid) {
                $rootScope.$broadcast('run.validation');
                return;
            }

            // If the "Preview Signatures before saving" checkbox is checked
            if ($scope.previewBeforeSavingCheckboxModel.checked === true) {
                var policyObject = $scope.preparePolicyData();

                CommonModalService.show({
                    templateUrl: 'modules/policy/views/previewPolicyModal.html',
                    size: 'lg',
                    controller: 'PolicySignaturesPreviewController',
                    resolve: {
                        submitCallback: function() {
                            return  $scope.createPolicy;
                        },
                        policyData: function() {
                            return policyObject;
                        },
                        submitBtnLbl: function() {
                            return $scope.btnTitleI18N;
                        }
                    }
                });
            }
            else {
                // Run Create Policy Function
                $scope.createPolicy();
            }
        };

        $scope.preparePolicyData = function() {
            var policyObject = {
                id: $scope.policyData.id,
                name: $scope.policyData.policyName,
                description: $scope.policyData.description,
                type: $scope.policyData.type.value
            };

            if ($scope.states.signatureSelectionEnabled) {
                policyObject.customSignatureIds = [];
                policyObject.customCategoryIds = [];

                angular.forEach($scope.policyData.selectedSignatures, function(selectedSignature) {
                    policyObject.customSignatureIds.push(selectedSignature.id);

                    if (policyObject.customCategoryIds.indexOf(selectedSignature.category_id) === -1) {
                        policyObject.customCategoryIds.push(selectedSignature.category_id);
                    }
                });
            }

            return policyObject;
        };

        $scope.createPolicy = function() {
            $scope.states.isPolicyDataSendingInProgress = true;

            var policyObject = $scope.preparePolicyData();

            ValidationService.ensureUnique(PolicyDataService.getPolicyNames(), policyObject,
                $scope.handlePolicyNameValidationResult);
        };

        $scope.handlePolicyNameValidationResult = function(isUnique, policyObject) {
            if (isUnique) {
                if ($scope.states.isEditMode) {
                    PolicyDataService.editPolicy(policyObject).then($scope.successHandler, $scope.errorEditHandler);
                } else {
                    PolicyDataService.createNewPolicy(policyObject).then($scope.successHandler,
                        $scope.errorCreateHandler);
                }
            } else {
                $scope.states.isPolicyDataSendingInProgress = false;
                CommonErrorMessageService.showErrorMessage("validationErrors.policyNameNotUnique", null,
                    "errors.formDataErrorCommonTitle");
            }
        };

        $scope.successHandler = function(createdPolicy) {
            // Redirecting to policies page with specific parameters
            CommonNavigationService.navigateToPoliciesGridPage();
            BroadcastService.changeTopLevelMessage({
                item: createdPolicy,
                id: createdPolicy.id,
                action: $scope.states.isEditMode ? gridStandardActions.edit : gridStandardActions.create
            });
        };

        $scope.errorCreateHandler = function(reason) {
            $scope.states.isPolicyDataSendingInProgress = false;
            CommonErrorMessageService.showErrorMessage("errors.createPolicyError", reason);
        };

        $scope.errorEditHandler = function(reason) {
            $scope.states.isPolicyDataSendingInProgress = false;
            CommonErrorMessageService.showErrorMessage("errors.editPolicyError", reason);
        };

        $scope.cancelCreation = function() {
            CommonNavigationService.navigateToPoliciesGridPage();
        };

        $scope.updatePolicyType = function() {
            if ($scope.policyData.selectedSignatures.length > 0) {
                $scope.validatePolicyTypeChange();
            } else {
                $scope.confirmTypeChange();
            }
        };

        $scope.validatePolicyTypeChange = function() {
            CommonModalService.show({
                templateUrl: 'modules/policy/views/policyChangeConfirmation.html',
                controller: 'PolicyChangeConfirmController',
                resolve: {
                    cancelCallback: function() {
                        return $scope.declineTypeChange;
                    },
                    submitCallback: function() {
                        return  $scope.confirmTypeChange;
                    },
                    title: function(){
                        return 'createPolicy.policyTypeChangeTitle';
                    },
                    msg: function(){
                        return 'createPolicy.policyTypeChangeMsg';
                    }
                }
            });

        };

        $scope.confirmTypeChange = function(){
            $scope.policyData.selectedSignatures = [];
            $scope.policyData.type = $scope._policyType;
            if (angular.isDefined($scope.policyData.type)) {
                $scope.states.signatureSelectionMode = $scope.policyData.type.signatureSelect;
                switch ($scope.policyData.type.signatureSelect) {
                    case 'categories':
                    case 'signatures':
                        $scope.states.signatureSelectionEnabled = true;
                        break;
                    default:
                        $scope.states.signatureSelectionEnabled = false;
                }
            }
        };

        $scope.declineTypeChange = function(){
            $scope._policyType = $scope.policyData.type;
        };

        $scope.processClonePolicyAction = function() {
            var clonePolicyData = GridActionsHelper.getGridCloneData();
            if (angular.isDefined(clonePolicyData)) {
                $scope.states.isCloneMode = true;

                $scope.pageTitleI18N = 'createPolicy.cloneTitle';
                $scope.btnTitleI18N = 'generalElements.clone';

                $scope.policyData.policyName = $i18next('createPolicy.clonePolicyPrefixAndName',
                    { postProcess: 'sprintf', sprintf: [clonePolicyData.name] });

                $scope.populateInputsWithData(clonePolicyData);

                GridActionsHelper.consumeGridCloneData();
            }
        };

        $scope.processEditPolicyAction = function() {
            var editPolicyData = GridActionsHelper.getGridEditData();
            if (angular.isDefined(editPolicyData)) {
                $scope.states.isEditMode = true;

                $scope.pageTitleI18N = 'createPolicy.editTitle';
                $scope.btnTitleI18N = 'generalElements.save';

                $scope.policyData.id = editPolicyData.id;
                $scope.policyData.policyName = editPolicyData.name;

                $scope.populateInputsWithData(editPolicyData);

                GridActionsHelper.consumeGridEditData();
            }
        };

        $scope.populateInputsWithData = function(dataObj) {
            $scope.policyData.description = dataObj.description;

            $scope.formData.validation = {
                name: true,
                description: true,
                category: true,
                signatures: true
            };

            var selectedPolicyType = {};
            var policyType;
            for (var i = 0; i < $scope.policyTypeList.length; i++) {
                policyType = $scope.policyTypeList[i];

                if (policyType.value === dataObj.policy_type) {
                    selectedPolicyType = policyType;
                    break;
                }
            }

            if (selectedPolicyType.signatureSelect && selectedPolicyType.signatureSelect.length > 0) {
                $scope.states.isPolicyDataSendingInProgress = true;

                PolicyDataService.getSignatures(dataObj.id).then(function success(data) {
                    $scope.preselectedData = data;

                    $scope.finishUpProcessingDetailsForEditOrClone(dataObj, selectedPolicyType);
                }, function error() {
                    $scope.finishUpProcessingDetailsForEditOrClone(dataObj, selectedPolicyType);
                });
            } else {
                $scope.finishUpProcessingDetailsForEditOrClone(dataObj, selectedPolicyType);
            }
        };

        $scope.finishUpProcessingDetailsForEditOrClone = function(dataObj, selectedPolicyType) {
            $scope.policyData.type = selectedPolicyType;
            $scope._policyType = selectedPolicyType;
            $scope.updatePolicyType();

            $scope.states.isPolicyDataSendingInProgress = false;
            $scope.checkValidationResult();
        };

        $scope.processClonePolicyAction();
        $scope.processEditPolicyAction();

    }]);
