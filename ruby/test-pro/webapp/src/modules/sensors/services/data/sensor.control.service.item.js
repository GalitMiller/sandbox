angular.module('bricata.ui.sensors')
    .factory('SensorControlItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.sensorControlItem, {}, {
                activate: {method:'POST'}
            });
        }]);