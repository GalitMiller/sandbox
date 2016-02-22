angular.module("bricata.uicore.grid")
    .directive("gridNoFilterResults", [
        function() {
            return {
                restrict : 'E',
                templateUrl : 'uicore/grid/views/grid-no-filter-results.html',
                scope: {
                    clearFilters: '&'
                },
                link: function(scope) {
                    scope.clearFilterCriteria = function() {
                        scope.clearFilters()();
                    };
                }
            };
        }]);