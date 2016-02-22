angular.module('bricata.ui.signature')
    .factory('SignatureProtocolItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureProtocols, {}, {
                query: {method:'GET'}
            });
        }]);