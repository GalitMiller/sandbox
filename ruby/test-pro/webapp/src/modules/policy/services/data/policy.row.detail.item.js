angular.module('bricata.ui.policy')
    .factory('PolicyDetailsInfo', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.policyDetailRequest,
                {entityId:'@id', rowId:'@row'}, {
                query: {method:'GET', isArray:false}
            });
        }]);