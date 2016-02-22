angular.module('bricata.ui.severity')
    .controller('CreateSeverityController',
    ['$scope', '$rootScope',
        'CommonNavigationService', 'BroadcastService', 'GridActionsHelper', 'gridStandardActions',
        'ValidationService', 'CommonErrorMessageService', 'SeverityDataService', 'SignatureDataService',
        function($scope, $rootScope,
                 CommonNavigationService, BroadcastService, GridActionsHelper, gridStandardActions,
                 ValidationService, CommonErrorMessageService, SeverityDataService, SignatureDataService) {

            $scope.pageTitleI18N = 'signatureSeverity.title';
            $scope.btnTitleI18N = 'generalElements.create';

            $scope.states = {
                isEditMode: false,
                isDataSendingInProgress: false
            };

            $scope.formData = {
                data: {
                    name: '',
                    weight: null,
                    bg_color: '#d9534f',
                    text_color: "#FFF"
                },
                validation: {
                    name: false,
                    priority: false,
                    bgClr: true,
                    txtClr: true
                }
            };

            $scope.$on('input.text.validation.processed', function(event, data) {
                switch (data.name) {
                    case 'signatureSeverityName':
                        $scope.formData.validation.name = data.isValid;
                        break;
                    case 'signatureSeverityPriority':
                        $scope.formData.validation.priority = data.isValid;
                        break;
                    case 'signatureSeverityBgColor':
                        $scope.formData.validation.bgClr = data.isValid;
                        break;
                    case 'signatureSeverityTxtColor':
                        $scope.formData.validation.txtClr = data.isValid;
                        break;
                }
            });

            $scope.submitSeverity = function() {
                if (!$scope.formData.validation.name || !$scope.formData.validation.priority ||
                    !$scope.formData.validation.bgClr || !$scope.formData.validation.txtClr) {
                    $rootScope.$broadcast('run.validation');
                } else {
                    $scope.createEditSeverity();
                }
            };

            $scope.processEditSeverityAction = function() {
                var editSeverityData = GridActionsHelper.getGridEditData();
                if (angular.isDefined(editSeverityData)) {
                    $scope.states.isEditMode = true;

                    $scope.pageTitleI18N = 'signatureSeverity.editTitle';
                    $scope.btnTitleI18N = 'generalElements.save';
                    $scope.formData.data = {
                        id: editSeverityData.id,
                        name: editSeverityData.name,
                        weight: editSeverityData.weight,
                        bg_color: editSeverityData.bg_color,
                        text_color: editSeverityData.text_color
                    };

                    GridActionsHelper.consumeGridEditData();
                }
            };

            $scope.createEditSeverity = function() {
                $scope.states.isDataSendingInProgress = true;

                ValidationService.ensureUnique(SignatureDataService.getSeverities(),
                    $scope.formData.data, $scope.handleSeverityNameValidationResult);
            };

            $scope.handleSeverityNameValidationResult = function(isUnique, severityObject) {
                if (isUnique) {
                    if ($scope.states.isEditMode) {
                        SeverityDataService.editSeverity(severityObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    } else {
                        SeverityDataService.createNewSeverity(severityObject)
                            .then($scope.successHandler, $scope.errorHandler);
                    }
                } else {
                    $scope.states.isDataSendingInProgress = false;
                    CommonErrorMessageService.showErrorMessage("validationErrors.severityNameNotUnique", null,
                        "errors.formDataErrorCommonTitle");
                }
            };

            $scope.successHandler = function(createdSeverity) {
                CommonNavigationService.navigateToSeverityGridPage();
                BroadcastService.changeTopLevelMessage({
                    item: createdSeverity,
                    id: createdSeverity.id,
                    action: $scope.states.isEditMode ? gridStandardActions.edit : gridStandardActions.create
                });
            };

            $scope.errorHandler = function(reason) {
                $scope.states.isDataSendingInProgress = false;
                var error = $scope.states.isEditMode ?
                    "errors.editSeverityError" : "errors.createSeverityError";
                CommonErrorMessageService.showErrorMessage(error, reason);
            };

            $scope.cancelWizard = function() {
                CommonNavigationService.navigateToSeverityGridPage();
            };

            $scope.processEditSeverityAction();

        }]);
