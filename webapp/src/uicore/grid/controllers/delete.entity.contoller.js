angular.module('bricata.uicore.grid')
    .controller('CommonDeleteEntityController',
    ['$scope', '$modalInstance', 'CommonModalService',
        'entityObjects', 'labels', 'deleteMethod', 'CommonErrorMessageService',
        function($scope, $modalInstance, CommonModalService,
                 entityObjects, labels, deleteMethod, CommonErrorMessageService) {

            $scope.entityItem = entityObjects[0];
            $scope.entityItems = entityObjects;
            $scope.msgs = labels;
            $scope.performDeletion = deleteMethod;

            $scope.isBulkMode = entityObjects.length > 1;
            $scope.isSendingDataInProgress = false;

            $scope.deleteThisEntity = function () {
                $scope.isSendingDataInProgress = true;
                var entityIds = [];

                angular.forEach($scope.entityItems, function(item) {
                    entityIds.push(item.id);
                });

                $scope.performDeletion(entityIds).then(function(data) {
                        if (data.failed && data.failed.length > 0) {
                            var reason = {};
                            reason.message = [];
                            angular.forEach(data.failed, function(item){
                                reason.message.push(item.name + ". " + item.message);
                            });
                            $scope.processError(reason);
                        } else {
                            $modalInstance.close($scope.entityItems);
                            CommonModalService.unbindRepositionOnResize();
                        }
                    }, function(reason) {
                        $scope.processError(reason);
                    }
                );
            };

            $scope.processError = function (reason) {
                $modalInstance.dismiss('cancel');
                CommonErrorMessageService.showErrorMessage($scope.msgs.errorTxt, reason);
            };

            $scope.closeDeleteModal = function () {
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
