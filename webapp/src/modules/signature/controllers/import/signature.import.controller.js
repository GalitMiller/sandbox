angular.module('bricata.ui.signature')
    .controller('ImportSignatureController',
    ['$scope', '$modalInstance', '$rootScope',
        'selectedCategory',
        'CommonModalService', 'CommonErrorMessageService', 'CommonAlertMessageService',
        function($scope, $modalInstance, $rootScope,
                 selectedCategory,
                 CommonModalService, CommonErrorMessageService, CommonAlertMessageService) {

            $scope.importPreviewData = {};
            $scope.isImportPreviewShown = false;

            $scope.model = {
                data: {
                    format: "suricata",
                    selectedFile: null
                }
            };

            $scope.$on('file.selected', function(event, data) {
                $scope.model.data.selectedFile = data;
            });

            $scope.importSignature = function() {
                if (!$scope.model.data.selectedFile) {
                    CommonErrorMessageService.showErrorMessage("errors.importUploadNoFileSelectedMsg",
                        null, "errors.importUploadNoFileSelectedTitle");
                    return;
                }

                if ($scope.model.data.selectedFile.size && $scope.model.data.selectedFile.size > 1048576) {
                    CommonAlertMessageService.showMessage("errors.importUploadFileSizeLimitTitle",
                        "errors.importUploadFileSizeLimitMsg", "errors.importUploadFileSizeLimitDetail",
                        $scope.closeImportModal, $scope.handlePreviewBackBtn);
                    $scope.isImportPreviewShown = true;
                    return;
                }

                $scope.processImport();
            };

            $scope.processImport = function() {
                $scope.isImportPreviewShown = true;
                CommonModalService.show({
                    templateUrl: 'modules/signature/views/import/save-signature-modal.html',
                    controller: 'ImportSignatureSaveController',
                    windowClass: 'import-signature-preview-modal-window',
                    resolve: {
                        selectedFile: function(){
                            return $scope.model.data.selectedFile;
                        },
                        importPreviewSubmitted: function() {
                            return $scope.submitDialog;
                        },
                        importPreviewBackHandler: function() {
                            return $scope.handlePreviewBackBtn;
                        },
                        importPreviewCancelled: function() {
                            return $scope.closeImportModal;
                        },
                        selectedCategory: function() {
                            return selectedCategory;
                        }
                    }
                });
            };

            $scope.handlePreviewBackBtn = function(){
                $scope.isImportPreviewShown = false;
                CommonModalService.centerModal();
            };

            $scope.submitDialog = function() {
                $rootScope.$emit('signature.select.refresh');
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();
            };

            $scope.closeImportModal = function () {
                $rootScope.$emit('enable.validation');
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
            };

            $modalInstance.opened.then(function() {
                $rootScope.$emit('disable.validation');
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
