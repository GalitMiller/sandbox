angular.module('bricata.ui.sensors')
    .factory('InterfaceItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.interfaceItems, {}, {
                query: {method:'GET'}
            });
        }]);