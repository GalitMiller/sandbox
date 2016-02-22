angular.module('bricata.ui.signaturecategories')
    .factory('SignatureCategorySignatures', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureCategorySignatures, {}, {
                query: {method:'GET'}
            });
        }]);