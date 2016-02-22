angular.module('bricata.ui.signature')
    .factory('SignatureImportUploadItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureImportUpload, {}, {
                upload: {method:'POST'}
            });
        }]);