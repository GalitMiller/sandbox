angular.module('bricata.ui.signature')
    .factory('SignatureCategoriesModel',
    ['$q', 'SignatureCategoriesDataService', 'CommonErrorMessageService',
        function ($q, SignatureCategoriesDataService, CommonErrorMessageService) {
            var pendingForUpdateCategories = [];
            var cachedData = {};
            var SIGNATURES_PER_PAGE = 1000;
            var signaturesToLoad = 0;

            var loadSignaturesForUpdatedCategories = function(progressValues, defferedMain, category, pageNum) {
                var categoryToUpdate = category ? category : pendingForUpdateCategories.shift();

                if (categoryToUpdate) {
                    var pageNumber = pageNum ? pageNum : 1;
                    SignatureCategoriesDataService.getCategorySignaturesPaginated(categoryToUpdate.id, '', pageNumber,
                        SIGNATURES_PER_PAGE).then(
                            function success(data) {
                                angular.forEach(data.objects, function (value) {
                                    value.category_id = categoryToUpdate.id;
                                    cachedData[categoryToUpdate.id].signatures.push(value);
                                });
                                progressValues.loadingSignaturesProgress +=
                                    Math.floor(99 * data.objects.length / signaturesToLoad);
                                loadSignaturesForUpdatedCategories(progressValues, defferedMain,
                                        data.page !== data.total_pages ? categoryToUpdate : null,
                                        data.page !== data.total_pages ? ++pageNumber : 1);
                            },
                            function error(reason){
                                cachedData[categoryToUpdate.id].signatures = [];
                                cachedData[categoryToUpdate.id].signatures_count = [];
                                CommonErrorMessageService.showErrorMessage("errors.signatureCategoriesLoadingError",
                                    reason);
                            }
                    );
                } else {
                    var arrData = [];
                    angular.forEach(cachedData, function (value) {
                        arrData.push(value);
                    });
                    defferedMain.resolve(arrData);
                }
            };

            var removeNotExistingCategories = function(latestCategories){
                var categoryExists;
                var removedCategoryIds = [];
                var parsedKey;
                angular.forEach(cachedData, function (value, key) {
                    categoryExists = false;
                    parsedKey = parseInt(key);
                    for (var i = 0; i < latestCategories.length; i++) {
                        if (latestCategories[i].id === parsedKey) {
                            categoryExists = true;
                            break;
                        }
                    }

                    if (!categoryExists) {
                        removedCategoryIds.push(key);
                    }

                    for (i = 0; i < removedCategoryIds.length; i++) {
                        delete cachedData[removedCategoryIds[i]];
                    }
                });
            };

            return {
                getData: function (progressValues) {
                    var deferred = $q.defer();
                    pendingForUpdateCategories = [];
                    SignatureCategoriesDataService.getCategoryUpdates().then(function success(data) {
                        removeNotExistingCategories(data);
                        signaturesToLoad = 0;
                        progressValues.loadingSignaturesProgress = 1;

                        for (var i = 0; i < data.length; i++) {
                            if ((!cachedData[data[i].id] ||
                                cachedData[data[i].id].signatures_count !== data[i].signatures_count) &&
                                data[i].signatures_count > 0) {

                                signaturesToLoad += data[i].signatures_count;

                                pendingForUpdateCategories.push(data[i]);
                                cachedData[data[i].id] = data[i];
                                cachedData[data[i].id].signatures = [];
                            } else if (data[i].signatures_count === 0) {
                                cachedData[data[i].id] = data[i];
                                cachedData[data[i].id].signatures = [];
                            } else {
                                cachedData[data[i].id].name = data[i].name;
                            }
                        }

                        if (pendingForUpdateCategories.length > 0) {
                            loadSignaturesForUpdatedCategories(progressValues, deferred);
                        } else {
                            var arrData = [];
                            angular.forEach(cachedData, function (value) {
                                arrData.push(value);
                            });
                            deferred.resolve(arrData);
                        }
                    },
                    function error(reason){
                        cachedData = {};
                        CommonErrorMessageService.showErrorMessage("errors.signatureCategoriesLoadingError", reason);
                    });

                    return deferred.promise;
                }
            };

        }]);