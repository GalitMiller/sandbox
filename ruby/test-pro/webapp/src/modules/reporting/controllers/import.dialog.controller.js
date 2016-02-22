angular.module('bricata.ui.reporting')
    .controller('ImportDialogController',
    ['$scope', '$modalInstance', '$rootScope', 'CommonModalService', 'CommonErrorMessageService',
        'importMethod', 'labels',
        function($scope, $modalInstance, $rootScope, CommonModalService, CommonErrorMessageService,
                 importMethod, labels) {

            $scope.labels = labels;
            $scope.states = {
                isLoading: false,
                isErrorReceived: false
            };

            $scope.selectedFile = null;
            $scope.failures = null;

            $scope.$on('file.selected', function(event, data) {
                $scope.selectedFile = data;
            });

            $scope.processImport = function() {
                if (!$scope.selectedFile) {
                    CommonErrorMessageService.showErrorMessage("errors.importUploadNoFileSelectedMsg",
                        null, "errors.importUploadNoFileSelectedTitle");
                    return;
                }

                $scope.states.isLoading = true;
                importMethod($scope.selectedFile).then(function(data) {
                    if (data.failed && data.failed.length > 0) {
                        $scope.failures = data.failed;
                        $scope.states.isErrorReceived = true;
                        $scope.states.isLoading = false;
                        $scope.$broadcast('content.changed');
                        CommonModalService.centerModal();
                    } else {
                        $scope.submitDialog();
                    }
                }, function(reason) {
                    $scope.states.isLoading = false;
                    CommonErrorMessageService.showErrorMessage("errors.importUploadFailedError", reason);
                });
            };

            $scope.submitDialog = function() {
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();
            };

            $scope.closeImportModal = function () {
                if ($scope.states.isErrorReceived) {
                    $scope.submitDialog();
                } else {
                    $modalInstance.dismiss('cancel');
                    CommonModalService.unbindRepositionOnResize();
                }
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
