angular.module('bricata.ui.signature')
    .controller('ImportSignatureSaveController',
    ['$scope', '$modalInstance', '$rootScope', 'selectedCategory',
        'BricataUris', 'CommonNavigationService', 'CommonProxyForRequests',
        'CommonModalService', 'CommonErrorMessageService', '$i18next',
        'selectedFile', 'importPreviewSubmitted', 'importPreviewBackHandler',
        'importPreviewCancelled', '$q', 'SignatureDataService',
        '$timeout', 'SignatureWizardService', 'SignatureImportHelperService',
        function($scope, $modalInstance, $rootScope, selectedCategory,
                 BricataUris, CommonNavigationService, CommonProxyForRequests,
                 CommonModalService, CommonErrorMessageService, $i18next,
                 selectedFile, importPreviewSubmitted, importPreviewBackHandler,
                 importPreviewCancelled, $q, SignatureDataService,
                 $timeout, SignatureWizardService, SignatureImportHelperService) {

            var initController = function() {
                $scope.importPreviewData = {};
                $scope.checkboxes = { 'checked': false, items: {} };
                $scope.uid = 0;

                $scope.states = {
                    isLoadingServiceData: true,
                    bulkSetupDisabled: true,
                    isPartialErrorMode: false,
                    isSignatureCategorySelectionDisabled: false
                };

                $scope.counters = {
                    checkedNum: 0,
                    validRulesCount: 0,
                    notificationsNum: 0
                };

                $scope.displayedRules = [];
                $scope.verticalScrollPosition = 0;

                $scope.topLvlSettings = {
                    category: null,
                    severity: null,
                    saveAsEditable: true
                };

                $scope.values = {
                    categories: [],
                    severities: [],
                    defaultCategory: null,
                    defaultSeverity: null
                };
            };

            initController();

            if (CommonNavigationService.isThisCurrentLocation(BricataUris.pages.signatureCategoriesPage)){
                $scope.states.isSignatureCategorySelectionDisabled = true;
            }

            $scope.loadServiceDataAndUploadImport = function() {
                $q.all([
                    SignatureDataService.getSignatureCategoriesLite(),
                    SignatureDataService.getSeverities(),
                    SignatureDataService.uploadImportFile(selectedFile)
                ]).then(function(data) {
                    var defaultSeveritySelection = {
                        id: -1,
                        priority: -1,
                        name: $i18next('importSignature.basedOnClassType')
                    };
                    $scope.values.categories = data[0];
                    $scope.values.severities = data[1];
                    $scope.values.severities.unshift(defaultSeveritySelection);
                    $scope.importPreviewData = data[2];


                    $scope.values.defaultCategory = selectedCategory ?
                        selectedCategory : $scope.importPreviewData.defaults.category;
                    $scope.values.defaultSeverity = defaultSeveritySelection;

                    $scope.initializeRuleValues();

                    $scope.states.isLoadingServiceData = false;
                    $scope.setUpPagination();
                }, function(reason) {
                    $scope.states.isLoadingServiceData = false;
                    CommonErrorMessageService.showErrorMessage("errors.importUploadFailedError", reason);
                    $scope.navToPreviousStep();
                });
            };

            $scope.initializeRuleValues = function() {
                angular.forEach($scope.importPreviewData.rules, function(rule) {
                    rule.uid = $scope.uid++;
                    if (rule.is_valid) {
                        rule.category = $scope.values.defaultCategory;
                        rule.severity = $scope.values.defaultSeverity;

                        $scope.checkboxes.items[rule.uid] = false;
                        $scope.counters.validRulesCount++;

                        if (angular.isDefined(rule.messages)) {
                            $scope.isNotificationPresent = true;
                            $scope.counters.notificationsNum++;
                            rule.hasNotification = true;
                        }
                    }
                });

                $scope.selectAll({target: {checked: true}});

                $scope.importSummary = {
                    status: $scope.counters.validRulesCount === $scope.importPreviewData.rules.length ? 'success' :
                        ($scope.counters.validRulesCount === 0 ? 'failure' : 'partial')
                };
            };

            $scope.setUpPagination = function() {
                $scope.pagination = {
                    totalItemsCount: $scope.importPreviewData.rules.length,
                    currentPage: 1,
                    maxSize: 5,
                    perPage: 100
                };

                $scope.pageChanged();
            };

            $scope.pageChanged = function(){
                var startPos = $scope.pagination.perPage * ($scope.pagination.currentPage - 1);
                $scope.displayedRules =
                    $scope.importPreviewData.rules.slice(startPos, startPos + $scope.pagination.perPage);

                $scope.$emit('content.changed');
                $scope.$emit('scrollable.scroll.top');
            };

            $timeout(function(){
                $scope.loadServiceDataAndUploadImport();
            }, 11, false);

            $scope.selectAll = function($event) {
                var value = $event.target.checked;
                $scope.checkboxes.checked = value;
                angular.forEach($scope.checkboxes.items, function(isChecked, key) {
                    $scope.checkboxes.items[key] = value;
                });

                $scope.processCheckBoxesChange();
            };

            $scope.processCheckBoxesChange = function(){
                $scope.counters.checkedNum = 0;
                var unchecked = 0,
                    total = $scope.counters.validRulesCount;

                angular.forEach($scope.checkboxes.items, function(isChecked) {
                    $scope.counters.checkedNum   +=  (isChecked) || 0;
                    unchecked += (!isChecked) || 0;
                });

                if ((unchecked === 0) || ($scope.counters.checkedNum === 0)) {
                    $scope.checkboxes.checked = ($scope.counters.checkedNum === total);
                }

                // grayed checkbox
                $scope.selectAllProp = $scope.counters.checkedNum !== 0 && unchecked !== 0;

                $scope.states.bulkSetupDisabled = $scope.counters.checkedNum === 0;

                SignatureImportHelperService.updateTopLvlSettings(
                    $scope.topLvlSettings,
                    $scope.importPreviewData.rules,
                    $scope.checkboxes.items);
            };

            $scope.topLvlCategoryChanged = function(){
                angular.forEach($scope.importPreviewData.rules, function(rule) {
                    if ($scope.checkboxes.items[rule.uid]) {
                        rule.category = $scope.topLvlSettings.category;
                    }
                });
            };

            $scope.topLvlSeverityChanged = function(){
                angular.forEach($scope.importPreviewData.rules, function(rule) {
                    if ($scope.checkboxes.items[rule.uid]) {
                        rule.severity = $scope.topLvlSettings.severity;
                    }
                });
            };

            $scope.singleCategoryChanged = function(){
                if ($scope.counters.checkedNum > 0) {
                    SignatureImportHelperService.updateTopLvlSettings(
                        $scope.topLvlSettings,
                        $scope.importPreviewData.rules,
                        $scope.checkboxes.items);
                }
            };

            $scope.singleSeverityChanged = function(){
                if ($scope.counters.checkedNum > 0) {
                    SignatureImportHelperService.updateTopLvlSettings(
                        $scope.topLvlSettings,
                        $scope.importPreviewData.rules,
                        $scope.checkboxes.items);
                }
            };

            $scope.checkImportValidationPassed = function(){
                var checkResult = SignatureImportHelperService.validateRules($scope.importPreviewData.rules,
                        $scope.counters.checkedNum > 0);

                if (checkResult.pRuleId.length > 0) {
                    $scope.$broadcast('scroll.to.element.id', {elementId: '#import_rule_' + checkResult.pRuleId});
                }

                return checkResult.result;
            };

            $scope.saveImport = function() {
                $scope.states.isLoadingServiceData = true;

                if (!$scope.checkImportValidationPassed()) {
                    $scope.states.isLoadingServiceData = false;

                    return;
                }

                var importsToSend = [];
                angular.forEach($scope.importPreviewData.rules, function(rule) {
                    if (rule.is_valid && $scope.checkboxes.items[rule.uid]) {
                        importsToSend.push({
                            name: rule.name,
                            rule: rule.source,
                            categoryId: rule.category.id,
                            severityId: rule.severity.id
                        });
                    }
                });

                SignatureDataService.saveImportFile(importsToSend,
                    $scope.topLvlSettings.saveAsEditable).then(function(data) {
                    if (data.failed && data.failed.length > 0) {
                        angular.forEach(data.failed, function(rule) {
                            rule.uid = $scope.uid++;
                        });
                        $scope.importPreviewData.rules = data.failed;
                        $scope.setUpPagination();

                        angular.forEach($scope.importPreviewData.rules, function(rule) {
                            rule.name = rule.rule.name;
                            rule.category =
                                SignatureImportHelperService.findEntityById($scope.values.categories,
                                    rule.rule.categoryId);
                            rule.severity =
                                SignatureImportHelperService.findEntityById($scope.values.severities,
                                    rule.rule.severityId);
                        });
                        $scope.states.isPartialErrorMode = true;

                        $scope.states.isLoadingServiceData = false;
                        CommonErrorMessageService.showErrorMessage($i18next("errors.importPartialProcessingError",
                                { postProcess: 'sprintf', sprintf: [data.failed.length, $scope.counters.checkedNum] }),
                            null, "errors.importPartialProcessingTitle");
                    } else {
                        $scope.submitDialog();
                    }

                }, function(reason) {
                    $scope.states.isLoadingServiceData = false;
                    CommonErrorMessageService.showErrorMessage("errors.importUploadFailedError", reason);
                });
            };

            $scope.navToPreviousStep = function() {
                importPreviewBackHandler();
                $modalInstance.close();
            };

            $scope.subModalCancel = function() {
                $scope.isSubModalShown = false;
                CommonModalService.centerModal();
            };

            $scope.openNewCategoryDialog = function() {
                SignatureWizardService.openNewSignatureCategoryDialog($scope.subModalCancel,
                    $scope.newCategoryCreated, $scope.values.categories);

                $scope.isSubModalShown = true;
            };

            $scope.newCategoryCreated = function(createdCategory) {
                $scope.subModalCancel();

                $scope.values.categories.unshift(createdCategory);
                $scope.topLvlSettings.category = createdCategory;
                $scope.topLvlCategoryChanged();
            };

            $scope.openNewSeverityDialog = function() {
                SignatureWizardService.openNewSignatureSeverityDialog($scope.subModalCancel,
                    $scope.newSeverityCreated, $scope.values.severities);

                $scope.isSubModalShown = true;
            };

            $scope.newSeverityCreated = function(createdSeverity) {
                $scope.subModalCancel();

                $scope.values.severities.unshift(createdSeverity);
                $scope.topLvlSettings.severity = createdSeverity;
                $scope.topLvlSeverityChanged();
            };

            $scope.submitDialog = function() {
                importPreviewSubmitted();
                $rootScope.$emit('enable.validation');
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();
            };

            $scope.closeImportSaveModal = function () {
                importPreviewCancelled();
                $rootScope.$emit('enable.validation');
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
                CommonProxyForRequests.cancelAllPendingRequests();
            };

            $modalInstance.opened.then(function() {
                $rootScope.$emit('disable.validation');
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
