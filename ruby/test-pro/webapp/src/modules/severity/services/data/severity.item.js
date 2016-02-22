angular.module('bricata.ui.severity')
    .factory('SeverityItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.severityItem, {}, {
                query: {method:'GET', isArray:false},
                delete: {method:'DELETE'},
                edit: {method:'PUT'},
                create: {method:'POST'}
            });
        }]);