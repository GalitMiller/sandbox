angular.module('bricata.ui.policy')
    .factory('PolicyAppliedInfo', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.policyAppliedInfo, {}, {
                query: {method:'GET'}
            });
        }]);