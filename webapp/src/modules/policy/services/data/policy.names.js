angular.module('bricata.ui.policy')
    .factory('PolicyItems', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.policyNames, {}, {
                query: {method:'GET', isArray:false}
            });
        }]);