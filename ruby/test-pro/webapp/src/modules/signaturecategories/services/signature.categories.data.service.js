angular.module("bricata.ui.signaturecategories")
    .factory("SignatureCategoriesDataService",
    ["CommonProxyForRequests", "SignatureCategoryItem", "SignatureCategorySignatures", "SignatureCategoryUpdates",
        function(CommonProxyForRequests, SignatureCategoryItem, SignatureCategorySignatures, SignatureCategoryUpdates){
            var service = {
                getSignatureCategoryItem:function(signatureCategoryItemId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryItem.query({id: signatureCategoryItemId}).$promise, true);
                },

                deleteSignatureCategoriesItem:function(signatureCategoriesIds){
                    var queryObject = {ids: signatureCategoriesIds};

                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                createNewSignatureCategory:function(newSignatureCategory) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryItem.create({id: ''}, newSignatureCategory).$promise, true);
                },

                editSignatureCategory:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryItem.edit({id: editData.id}, editData).$promise, true);
                },

                getCategorySignaturesPaginated:function(signatureCategoryItemId, searchedName, pageNum, resPerPage) {
                    var resultsPerPage = resPerPage ? resPerPage : 100;
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategorySignatures.query({
                            id: signatureCategoryItemId,
                            results_per_page: resultsPerPage,
                            page: pageNum,
                            q: searchedName
                        }).$promise, true);
                },

                getCategoryUpdates:function() {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryUpdates.query({
                            results_per_page: 10000
                        }).$promise, false, 'name');
                }
            };
            return service;
        }]);