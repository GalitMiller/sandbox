angular.module('bricata.ui.policy')
    .factory('PolicyItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.policyItem, {}, {
                query: {method:'GET', isArray:false},
                delete: {method:'DELETE'},
                create: {method:'POST'},
                preview: {method:'POST'},
                edit: {method:'PUT'}
            });
        }]);