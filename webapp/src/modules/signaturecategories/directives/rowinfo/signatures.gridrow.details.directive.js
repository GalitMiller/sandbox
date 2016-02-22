angular.module("bricata.ui.signaturecategories")
    .directive("signatureCategoriesGridRowDetails", [
        '$rootScope', 'gridStandardActions',
        'SignatureCategoriesDataService', 'CommonErrorMessageService',
        function($rootScope, gridStandardActions,
            SignatureCategoriesDataService, CommonErrorMessageService) {
            return {
                restrict : 'E',
                templateUrl :
                    'modules/signaturecategories/views/rowinfo/signature-category-grid-row-details-content.html',
                link: function(scope) {
                    scope.signatureCategoryDetailsLoaded = false;
                    scope.signatureCategoryDetailsLoadError = false;
                    scope.categorySignaturesLoadMethod = SignatureCategoriesDataService.getCategorySignaturesPaginated;

                    scope.loadSignatureCategoryDetails = function() {
                        SignatureCategoriesDataService.getSignatureCategoryItem(scope.selectedRow.id)
                            .then(function(data) {
                                if (data.objects[0]) {
                                    scope.selectedRow.signatures_count = data.objects[0].signatures_count;

                                    scope.signatureCategoryDetails = data.objects[0];

                                    scope.signatureCategoryDetailsLoaded = true;

                                    scope.$broadcast('content.changed');
                                } else {
                                    scope.handleError();
                                }
                        }, function error(reason) {
                            scope.handleError(reason);
                        });
                    };

                    scope.collapseDetails = function() {
                        scope.selectedRow.$selected = false;
                    };

                    scope.handleError = function(reason) {
                        if (!scope.signatureCategoryDetailsLoadError) {
                            scope.signatureCategoryDetailsLoadError = true;
                            CommonErrorMessageService.showErrorMessage(
                                "errors.signatureCategoryDetailsDataError", reason, null, scope.processError);
                        }
                    };

                    scope.processError = function() {
                        scope.signatureCategoryDetailsLoaded = true;
                    };

                    scope.reloadSignatureCategoryDetails = function() {
                        scope.signatureCategoryDetailsLoaded = false;
                        scope.signatureCategoryDetailsLoadError = false;

                        scope.loadSignatureCategoryDetails();
                    };

                    var unbindRootScopeListener = $rootScope.$on('signature.select.refresh', function() {
                        scope.reloadSignatureCategoryDetails();
                    });

                    scope.addNewSignature = function() {
                        var eventData = {
                            actionName: "addNewSignature",
                            actionType: "modal",
                            data: [{id: scope.selectedRow.id}]
                        };

                        scope.$emit('grid.header.invoke.row.action', eventData);
                    };

                    scope.importSignatures = function () {
                        var eventData = {
                            actionName: "importSignatures",
                            actionType: "modal",
                            data: [scope.selectedRow]
                        };

                        scope.$emit('grid.header.invoke.row.action', eventData);
                    };

                    scope.loadSignatureCategoryDetails();

                    var unbindDestroy = scope.$on("$destroy", function() {
                        unbindRootScopeListener();
                        unbindDestroy();
                    });
                }
            };
        }]);