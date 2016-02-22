angular.module('bricata.ui.signaturecategories')
    .factory('SignatureCategoryUpdates', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureCategoriesUpdates, {}, {
                query: {method:'GET'}
            });
        }]);