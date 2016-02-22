angular.module('bricata.ui.signature')
    .controller('SignatureSelectController',
    ['$scope', '$rootScope', 'SignatureCategoriesModel', 'CommonModalService', 'SignatureSelectionService',
        function($scope, $rootScope, SignatureCategoriesModel, CommonModalService, SignatureSelectionService) {

            $scope.categoriesSelectionUpdater = {};
            $scope.signaturesSelectionUpdater = {};

            $scope.isSignatureSelectionEnabled = false;

            $scope.availableSignatures = [];
            $scope.currentlySelectedCategoryIDs = [];
            $scope.currentlySelectedSignatureIDs = [];

            $scope.progressValues = {
                loadingSignaturesProgress: 0
            };

            $scope.isLoadingSignatureCategories = true;
            SignatureCategoriesModel.getData($scope.progressValues).then(function success(data) {
                $scope.signatureCategories = data;

                $scope.checkPreselection();
                $scope.isLoadingSignatureCategories = false;
            });

            $scope.reloadSignatureCategories = function(newCategoryData) {
                $scope.clearAll();
                $scope.isLoadingSignatureCategories = true;
                $scope.progressValues.loadingSignaturesProgress = 0;
                SignatureCategoriesModel.getData($scope.progressValues).then(function success(data) {
                    $scope.signatureCategories = data;

                    var selectedIds = SignatureSelectionService.extractSelectedIds($scope.currentlySelectedCategoryIDs);

                    if (newCategoryData) {
                        selectedIds.push(newCategoryData.id);
                    }

                    if (selectedIds.length > 0) {
                        $scope.categoriesSelectionUpdater.updateSelection(selectedIds.join(), true, true);

                        if ($scope.isSignatureSelectionEnabled) {
                            selectedIds =
                                SignatureSelectionService.extractSelectedIds($scope.currentlySelectedSignatureIDs);

                            $scope.signaturesSelectionUpdater.updateSelection(selectedIds.join(), true, true);
                        }
                    }

                    $scope.isLoadingSignatureCategories = false;
                });
            };

            var unbindRootScopeListener = $rootScope.$on('signature.select.refresh', function(event, data) {
                $scope.reloadSignatureCategories(data);
            });

            $scope.categorySelectionChange = function(selectedCategoryIDs) {
                $scope.currentlySelectedCategoryIDs = selectedCategoryIDs;

                SignatureSelectionService.processCategorySelectionChange(selectedCategoryIDs,
                    $scope.signatureCategories,
                    $scope.isSignatureSelectionEnabled ? $scope.availableSignatures : $scope.selectionModel);

                SignatureSelectionService.sortById($scope.isSignatureSelectionEnabled ?
                    $scope.availableSignatures : $scope.selectionModel);
            };

            /* Selecting Available Signatures and passing them to Selected Signatures
             @selectedSignatureIDs - object with all checked signatures ids - {1: true, 2: true ...}
             */
            $scope.signaturesSelectionChange = function (selectedSignatureIDs) {
                $scope.currentlySelectedSignatureIDs = selectedSignatureIDs;

                SignatureSelectionService.processSignatureSelectionChange(selectedSignatureIDs,
                    $scope.availableSignatures, $scope.selectionModel);

                SignatureSelectionService.sortById($scope.selectionModel);
            };

            $scope.clearAll = function() {
                $scope.selectionModel = [];
                $scope.availableSignatures = [];
                $scope.signaturesSelectionUpdater.updateSelection('', false);
                $scope.categoriesSelectionUpdater.updateSelection('', false);
            };

            // Clearing all items from selected signatures
            $scope.clearAllSelected = function() {
                $scope.selectionModel = [];
                $scope.signaturesSelectionUpdater.updateSelection('', false);

                if (!$scope.isSignatureSelectionEnabled) {
                    $scope.availableSignatures = [];
                    $scope.categoriesSelectionUpdater.updateSelection('', false);
                }
            };

            // Remove current clicked signature
            $scope.removeSelection = function(removedSignatureId) {
                var removedSignatureIdNumber = parseInt(removedSignatureId);

                var signature;
                for (var index = 0; index < $scope.selectionModel.length; index++) {
                    signature = $scope.selectionModel[index];

                    if (signature.id === removedSignatureIdNumber) {
                        $scope.selectionModel.splice(index, 1);
                        $scope.signaturesSelectionUpdater.updateSelection(removedSignatureId, false);
                        break;
                    }
                }
            };

            $scope.changeSelectionMode = function() {
                $scope.clearAll();

                switch ($scope.selectionMode) {
                    case 'categories':
                        $scope.isSignatureSelectionEnabled = false;
                        break;
                    case 'signatures':
                        $scope.isSignatureSelectionEnabled = true;
                        $scope.categoriesSelectionUpdater.updateSelection('', false);
                        break;
                }
            };

            $scope.checkPreselection = function() {
                if ($scope.preselectionModel.length > 0) {

                    var signatureCategories = [];
                    var signatures = [];
                    angular.forEach($scope.preselectionModel, function(selectedSignature) {
                        if (signatureCategories.indexOf(selectedSignature.category_id) === -1) {
                            signatureCategories.push(selectedSignature.category_id);
                        }
                        if ($scope.isSignatureSelectionEnabled) {
                            signatures.push(selectedSignature.id);
                        }
                    });
                    $scope.categoriesSelectionUpdater.updateSelection(signatureCategories.join(), true, true);

                    if ($scope.isSignatureSelectionEnabled) {
                        $scope.signaturesSelectionUpdater.updateSelection(signatures.join(), true, true);
                    }
                }

                $scope.preselectionModel.splice(0, $scope.preselectionModel.length);
            };

            /* ########################################
             Import Signature - Importing rules files
             ######################################## */
            $scope.openImportSignatureModal = function() {
                CommonModalService.show({
                    templateUrl: 'modules/signature/views/import/import-signature-modal.html',
                    controller: 'ImportSignatureController',
                    resolve: {
                        selectedCategory: null
                    }
                });
            };

            /* ########################################
             Add New Signature Wizard
             ######################################## */
            $scope.addNewSignature = function() {

                CommonModalService.show({
                    templateUrl: 'modules/signature/views/newsignature/add-new-signature-modal.html',
                    windowClass: 'new-signature-modal-window',
                    controller: 'NewSignatureModalController',
                    resolve: {
                        categoryId: function(){
                            return null;
                        }
                    }
                });

            };

            var unbindDestroy = $scope.$on("$destroy", function() {
                unbindRootScopeListener();
                unbindDestroy();
            });

        }]);
