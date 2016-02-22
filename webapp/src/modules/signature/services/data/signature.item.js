angular.module('bricata.ui.signature')
    .factory('SignatureItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signaturesItem, {}, {
                query: {method:'GET', isArray:false},
                delete: {method:'DELETE'},
                edit: {method:'PUT'},
                save: {method:'POST'}
            });
        }]);