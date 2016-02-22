angular.module('bricata.ui.signature')
    .factory('SignatureMappingItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureMappingItem, {}, {
                query: {method:'GET', isArray:false}
            });
        }]);