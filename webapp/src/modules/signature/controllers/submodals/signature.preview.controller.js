angular.module('bricata.ui.signature')
    .controller('SignaturePreviewController',
    ['$scope', '$modalInstance', 'CommonModalService', 'cancelCallback', 'submitCallback', 'ruleString',
        function($scope, $modalInstance, CommonModalService, cancelCallback, submitCallback, ruleString) {

            $scope.ruleTxt = ruleString.rule;

            $modalInstance.opened.then(function() {
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

            $scope.closePreviewModal = function () {
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                cancelCallback();
            };

            $scope.savePreviewedSignature = function() {
                $modalInstance.close();
                CommonModalService.unbindRepositionOnResize();

                submitCallback();
            };
        }]);
