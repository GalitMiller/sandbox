angular.module('bricata.ui.signatureclasstypes')
    .factory('SignatureClassTypeItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureClassTypeItem, {}, {
                query: {method:'GET', isArray:false},
                create: {method:'POST'},
                edit: {method:'PUT'},
                delete: {method:'DELETE'}
            });
        }]);