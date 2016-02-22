angular.module('bricata.ui.policy')
    .controller('PolicyChangeConfirmController',
    ['$scope', '$modalInstance', 'CommonModalService', 'cancelCallback', 'submitCallback', 'title', 'msg',
        function($scope, $modalInstance, CommonModalService, cancelCallback, submitCallback, title, msg) {

            $scope.titleTxt = title;
            $scope.msgTxt = msg;

            $scope.cancelModal = function () {
                cancelCallback();

                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
            };

            $scope.submitModal = function () {
                submitCallback();

                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
