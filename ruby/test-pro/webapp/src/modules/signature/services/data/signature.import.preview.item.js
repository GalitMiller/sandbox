angular.module('bricata.ui.signature')
    .factory('SignatureImportPreviewItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureImportPreview, {}, {
                upload: {method:'POST', headers: {'Content-Type': undefined }}
            });
        }]);