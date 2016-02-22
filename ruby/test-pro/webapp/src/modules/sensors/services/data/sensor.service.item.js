angular.module('bricata.ui.sensors')
    .factory('SensorItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.sensorsControlled, {rowId:'@row'}, {
                query: {method:'GET', isArray:false}
            });
        }]);