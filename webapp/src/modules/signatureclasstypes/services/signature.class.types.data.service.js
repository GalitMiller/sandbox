angular.module("bricata.ui.signatureclasstypes")
    .factory("SignatureClassTypesDataService",
    ["CommonProxyForRequests", "SignatureClassTypeItem", "ClassTypeImportUploadItem",
        function(CommonProxyForRequests, SignatureClassTypeItem, ClassTypeImportUploadItem){
            return {
                getSignatureClassTypeItem:function(signatureClassTypeItemId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureClassTypeItem.query({id: signatureClassTypeItemId}).$promise, true);
                },

                deleteSignatureClassTypeItem:function(signatureClassTypeIds){
                    var queryObject = {ids: signatureClassTypeIds};

                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureClassTypeItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                createNewSignatureClassTypeItem:function(newSignatureClassType) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureClassTypeItem.create({id: ''}, newSignatureClassType).$promise, true);
                },

                editSignatureClassTypeItem:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureClassTypeItem.edit({id: editData.id}, editData).$promise, true);
                },

                uploadImportFile: function(selectedFile){
                    var fd = new FormData();
                    fd.append('file', selectedFile, selectedFile.name);

                    return CommonProxyForRequests.getDecoratedPromise(
                        ClassTypeImportUploadItem.upload(fd).$promise, true);
                }
            };
        }]);