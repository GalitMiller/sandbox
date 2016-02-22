angular.module('bricata.ui.signature')
    .controller('SignatureNewCategoryController',
    ['$scope', '$modalInstance', '$rootScope', 'CommonModalService', 'CommonErrorMessageService',
        'cancelCallback', 'submitCallback', 'existingCategories', 'SignatureCategoriesDataService',
        function($scope, $modalInstance, $rootScope, CommonModalService, CommonErrorMessageService,
                 cancelCallback, submitCallback, existingCategories, SignatureCategoriesDataService) {

            $scope.isDataLoading = false;

            $scope.model = {
                data: {
                    name: ""
                },
                validation: {
                    name: false
                }
            };

            $modalInstance.opened.then(function() {
                $rootScope.$broadcast('disable.validation');
                CommonModalService.centerModal();
                CommonModalService.bindRepositionOnResize();
            });

            $scope.closeCategoryModal = function () {
                $rootScope.$broadcast('enable.validation');
                $modalInstance.dismiss('cancel');
                CommonModalService.unbindRepositionOnResize();

                cancelCallback();
            };

            $scope.saveSignatureCategory = function() {
                if (!$scope.model.validation.name) {
                    $rootScope.$broadcast('run.validation', {group: 'signatureCategoryValidation'});
                    return;
                }

                var isUnique = true;
                var category;
                for (var i = 0; i < existingCategories.length; i++) {
                    category = existingCategories[i];

                    if (category.name === $scope.model.data.name) {
                        isUnique = false;
                        break;
                    }
                }

                if (!isUnique) {
                    CommonErrorMessageService.showErrorMessage("validationErrors.signatureCategoryNameNotUnique", null,
                        "errors.formDataErrorCommonTitle");
                    return;
                }

                $scope.isDataLoading = true;
                SignatureCategoriesDataService.createNewSignatureCategory($scope.model.data).then(
                function success(data) {
                    $rootScope.$broadcast('enable.validation');
                    $modalInstance.close();
                    CommonModalService.unbindRepositionOnResize();

                    submitCallback(data);
                }, function(reason) {
                    $scope.isDataLoading = false;
                    CommonErrorMessageService.showErrorMessage("errors.createCategoryError", reason);
                });
            };

            $scope.$on('input.text.validation.processed', function(event, data) {
                if (angular.isDefined(data) && angular.isDefined(data.name) && data.name === 'signatureCategoryName') {
                    $scope.model.validation.name = data.isValid;
                }
            });
        }]);
