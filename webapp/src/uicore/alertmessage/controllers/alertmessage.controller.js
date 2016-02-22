angular.module('bricata.uicore.alertmsg')
    .controller('AlertMessageModalController',
    ['$scope', '$modalInstance', 'CommonModalService', 'messageObject',
        function($scope, $modalInstance, CommonModalService, messageObject) {

            $scope.messageObject = messageObject;

            $scope.closeAlertMessageModal = function(externalCancelHandler) {
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();

                if (externalCancelHandler) {
                    externalCancelHandler();
                }
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
