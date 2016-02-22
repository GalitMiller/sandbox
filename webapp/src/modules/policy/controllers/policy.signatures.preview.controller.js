angular.module('bricata.ui.policy')
    .controller('PolicySignaturesPreviewController',
    ['$scope', '$modalInstance', 'CommonModalService', '$timeout', 'PolicyDataService',
        'policyData', 'submitCallback', 'submitBtnLbl',
        function($scope, $modalInstance, CommonModalService, $timeout, PolicyDataService,
                 policyData, submitCallback, submitBtnLbl) {

            $scope.isRulesLoading = true;
            $scope.submitLbl = submitBtnLbl;
            $scope.displayedRules = [];

            $scope.pagination = {
                currentPage: 1,
                maxSize: 5,
                perPage: 100
            };

            $scope.pageChanged = function(){
                $scope.isRulesLoading = true;

                PolicyDataService.previewPolicy(policyData, $scope.pagination.currentPage).then(function(data) {
                    $scope.rules = data;
                    $scope.pagination.totalItemsCount = data.num_results;
                    $scope.displayedRules = data.objects;

                    $scope.isRulesLoading = false;

                    $scope.$emit('content.changed');
                    $scope.$emit('scrollable.scroll.top');
                });
            };

            $scope.pageChanged();

            $scope.cancelModal = function () {
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

                $timeout(function(){
                    $scope.$broadcast('content.changed');
                }, 333, false);
            });

        }]);
