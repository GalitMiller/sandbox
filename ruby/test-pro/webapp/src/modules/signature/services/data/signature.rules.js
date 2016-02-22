angular.module('bricata.ui.signature')
    .factory('SignatureRules', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signaturesRules, {}, {
                query: {method:'GET', isArray:false}
            });
        }]);