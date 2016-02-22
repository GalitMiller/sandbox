angular.module('bricata.uicore.grid')
    .factory('FilterValueItem', ['$resource', 'GridConfiguration',
        function($resource, GridConfiguration){
            return $resource(GridConfiguration.getFilterRequestUrl(), {entityId:'@id'}, {
                query: {method:'GET', isArray:false}
            });
        }]);
