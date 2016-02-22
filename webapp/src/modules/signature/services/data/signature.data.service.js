angular.module('bricata.ui.signature')
    .factory("SignatureDataService",
    ["BricataUris",
        "SignaturePreviewItem", "SignatureGetSIDId",
        "SignatureClassTypeItem", "SignatureReferenceTypeItem", "SignatureSeverityItem",
        "SignatureImportPreviewItem", "SignatureCategoryLiteItem", "SignatureImportUploadItem",
        "SignatureProtocolItem", "SignatureItem", "CommonProxyForRequests", "SignatureRules",
        "SignatureMappingItem",
        function (BricataUris,
                  SignaturePreviewItem, SignatureGetSIDId,
                  SignatureClassTypeItem, SignatureReferenceTypeItem, SignatureSeverityItem,
                  SignatureImportPreviewItem, SignatureCategoryLiteItem, SignatureImportUploadItem,
                  SignatureProtocolItem, SignatureItem, CommonProxyForRequests, SignatureRules,
                  SignatureMappingItem) {
            return {

                createSignature: function (data) {
                    return CommonProxyForRequests.getDecoratedPromise(SignatureItem.save(data).$promise, true);
                },

                sendDataForPreview: function (data) {
                    return CommonProxyForRequests.getDecoratedPromise(SignaturePreviewItem.singlePreview(data).$promise,
                        true);
                },

                getSignatureSID: function (data) {
                    return CommonProxyForRequests.getDecoratedPromise(SignatureGetSIDId.get(data).$promise, true);
                },

                getSignatureCategoriesLite:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureCategoryLiteItem.query({results_per_page: 1000}).$promise, false, 'name');
                },

                getClassTypes:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureClassTypeItem.query({results_per_page: 1000}).$promise, false, 'name');
                },

                getReferenceTypes:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureReferenceTypeItem.query({results_per_page: 1000}).$promise, false, 'name');
                },

                getSeverities:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureSeverityItem.query({results_per_page: 1000}).$promise, false, 'priority');
                },

                getProtocols:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureProtocolItem.query({results_per_page: 1000}).$promise, false, 'name');
                },

                createSeverity: function(newSeverityData){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureSeverityItem.save(newSeverityData).$promise, true);
                },

                uploadImportFile: function(selectedFile){
                    var fd = new FormData();
                    fd.append('file', selectedFile, selectedFile.name);

                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureImportPreviewItem.upload(fd).$promise, true);
                },

                saveImportFile: function(importRules, isEditable){
                    var data = {
                        rules: importRules,
                        editable: isEditable
                    };

                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureImportUploadItem.upload(data).$promise, true);
                },

                getSignature:function(signatureId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureItem.query({id: signatureId}).$promise, true);
                },

                getSignatureRules:function(signatureId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureRules.query({
                            id: signatureId
                        }).$promise);
                },

                deleteSignature:function(signatureIds){
                    var queryObject = {ids: signatureIds};

                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                editSignature:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureItem.edit({id: editData.id}, editData).$promise, true);
                },

                getSignatureMappings:function(signatureSID){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SignatureMappingItem.query({id: signatureSID}).$promise);
                }
            };

        }]);