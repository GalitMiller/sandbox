angular.module('bricata.ui.sensors')
    .factory('InactiveSensorItemCount', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.inactiveSensorItemCount, {}, {
                query: {method:'GET'}
            });
        }]);