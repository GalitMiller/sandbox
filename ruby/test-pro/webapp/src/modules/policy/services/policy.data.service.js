angular.module("bricata.ui.policy")
    .factory("PolicyDataService",
    ["CommonProxyForRequests", "BricataUris", "PolicyItem", "PolicyDetailsInfo", "PolicyItems",
        function(CommonProxyForRequests, BricataUris, PolicyItem, PolicyDetailsInfo, PolicyItems){
            var service = {
                getPolicy:function(policyId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItem.query({id: '/'+policyId}).$promise, true);
                },

                deletePolicies:function(policyIds){
                    var queryObject = {ids: policyIds};

                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                createNewPolicy:function(newPolicyObject) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItem.create({id: ''}, newPolicyObject).$promise, true);
                },

                editPolicy:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItem.edit({id: '/' + editData.id}, editData).$promise, true);
                },

                previewPolicy: function(policyData, pageNum){
                    var previewData = {
                        customSignatureIds: policyData.customSignatureIds,
                        customCategoryIds: policyData.customCategoryIds,
                        type: policyData.type
                    };

                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItem.preview({
                                id: BricataUris.policyPreviewAction,
                                results_per_page: 100,
                                page: pageNum
                            },
                            previewData).$promise, true);
                },

                getSensors:function(queryParam, searchedName, pageNum){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyDetailsInfo.query({
                            entityId: BricataUris.policyDetailSensors,
                            rowId: queryParam,
                            results_per_page: 100,
                            page: pageNum,
                            q: searchedName
                        }).$promise, true);
                },

                getSignatures:function(queryParam){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyDetailsInfo.query({
                            entityId: BricataUris.policyDetailSignatures,
                            rowId: queryParam,
                            results_per_page: 100000
                        }).$promise);
                },

                getSignaturesPaginated:function(queryParam, searchedName, pageNum){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyDetailsInfo.query({
                            entityId: BricataUris.policyDetailSignatures,
                            rowId: queryParam,
                            results_per_page: 100,
                            page: pageNum,
                            q: searchedName
                        }).$promise, true);
                },

                getPolicyNames:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        PolicyItems.query({results_per_page: 1000}).$promise, false, 'name');
                }
            };
            return service;
        }]);