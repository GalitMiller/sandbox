angular.module('bricata.ui.referencetype')
    .factory("ReferenceTypeDataService",
    ["BricataUris", "CommonProxyForRequests", "ReferenceTypeItem", "ReferenceImportUploadItem",
        function (BricataUris, CommonProxyForRequests, ReferenceTypeItem, ReferenceImportUploadItem) {
            return {

                getReferenceType:function(referenceId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        ReferenceTypeItem.query({id: referenceId}).$promise, true);
                },

                deleteReferenceType:function(referenceIds){
                    var queryObject = {ids: referenceIds};

                    return CommonProxyForRequests.getDecoratedPromise(
                        ReferenceTypeItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                editReferenceType:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        ReferenceTypeItem.edit({id: editData.id}, editData).$promise, true);
                },

                createNewReferenceType:function(newReference) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        ReferenceTypeItem.create({id: ''}, newReference).$promise, true);
                },

                uploadImportFile: function(selectedFile){
                    var fd = new FormData();
                    fd.append('file', selectedFile, selectedFile.name);

                    return CommonProxyForRequests.getDecoratedPromise(
                        ReferenceImportUploadItem.upload(fd).$promise, true);
                }
            };

        }]);