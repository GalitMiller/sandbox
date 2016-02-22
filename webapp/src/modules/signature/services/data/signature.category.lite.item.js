angular.module('bricata.ui.signature')
    .factory('SignatureCategoryLiteItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureCategories, {}, {
                query: {method:'GET'}
            });
        }]);