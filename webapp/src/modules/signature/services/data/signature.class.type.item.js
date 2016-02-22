angular.module('bricata.ui.signature')
    .factory('SignatureClassTypeItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureClassTypes, {}, {
                query: {method:'GET', isArray:false}
            });
        }]);