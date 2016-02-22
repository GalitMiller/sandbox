angular.module('bricata.ui.signature')
    .factory('SignatureReferenceTypeItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureReferenceTypes, {}, {
                query: {method:'GET', isArray:false}
            });
        }]);