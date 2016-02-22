angular.module('bricata.ui.reporting')
    .controller('ExportDialogController',
    ['$scope', '$modalInstance', 'CommonModalService', 'labels', 'selectedCount', 'exportHandler',
        function($scope, $modalInstance, CommonModalService, labels, selectedCount, exportHandler) {

            $scope.labels = labels;
            $scope.selectedCount = selectedCount;
            $scope.model = {
                type: 'all'
            };

            $scope.performExport = function() {
                exportHandler($scope.model.type === 'all');
                $scope.closeExportModal();
            };

            $scope.closeExportModal = function () {
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                $scope.$destroy();
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
