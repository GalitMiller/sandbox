angular.module('bricata.ui.signaturecategories')
    .factory('SignatureCategoryItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureCategoryItem, {}, {
                query: {method:'GET', isArray:false},
                create: {method:'POST'},
                edit: {method:'PUT'},
                delete: {method:'DELETE'}
            });
        }]);