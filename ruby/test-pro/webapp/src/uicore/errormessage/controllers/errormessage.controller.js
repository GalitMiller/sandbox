angular.module('bricata.uicore.errormsg')
    .controller('ErrorMessageModalController',
    ['$scope', '$sce', '$modalInstance', 'CommonModalService', 'messageObject',
        function($scope, $sce, $modalInstance, CommonModalService, messageObject) {

            $scope.messageObject = messageObject;

            $scope.trustedHtmlMassage = function(html){
                return $sce.trustAsHtml(html);
            };

            $scope.closeErrorMessageModal = function () {
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();
            };

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

        }]);
