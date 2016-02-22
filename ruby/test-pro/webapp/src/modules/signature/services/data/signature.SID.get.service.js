angular.module('bricata.ui.signature')
    .factory('SignatureGetSIDId', ['$resource', 'BricataUris',
        function($resource, BricataUris){

            return $resource(BricataUris.sidIDNumber, {}, {
                get: {method: 'GET'}
            });

        }]);