angular.module('bricata.ui.signatureclasstypes')
    .factory('ClassTypeImportUploadItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureClassTypeImportUpload, {}, {
                upload: {method:'POST', headers: {'Content-Type': undefined }}
            });
        }]);