angular.module('bricata.ui.policy')
    .factory('PolicyApplication', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.policyApplication, {}, {
                apply: {method:'POST'}
            });
        }]);