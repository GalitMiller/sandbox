angular.module('bricata.ui.referencetype')
    .factory('ReferenceImportUploadItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.referenceImportUpload, {}, {
                upload: {method:'POST', headers: {'Content-Type': undefined }}
            });
        }]);