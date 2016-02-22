angular.module('bricata.ui.configuration')
    .factory('ConfigurationItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.configurationUrl, {}, {
                query: {method: 'GET'}
            });

        }]);