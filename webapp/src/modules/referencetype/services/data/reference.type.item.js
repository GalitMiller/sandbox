angular.module('bricata.ui.referencetype')
    .factory('ReferenceTypeItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.referenceTypeItem, {}, {
                query: {method:'GET', isArray:false},
                delete: {method:'DELETE'},
                edit: {method:'PUT'},
                create: {method:'POST'}
            });
        }]);