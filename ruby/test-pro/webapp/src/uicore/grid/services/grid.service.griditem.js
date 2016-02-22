angular.module('bricata.uicore.grid')
.factory('CommonGridItem', ['$resource', 'GridConfiguration',
        function($resource, GridConfiguration){
            return $resource(GridConfiguration.getGridRequestUrl(), {entityId:'@id', query:'@q'}, {
                query: {method:'GET', isArray:false}
            });
}]);