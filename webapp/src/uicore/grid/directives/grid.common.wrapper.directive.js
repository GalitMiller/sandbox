angular.module("bricata.uicore.grid")
    .directive("commonGridWrapper", [
        function() {
            return {
                restrict : 'E',
                templateUrl : 'uicore/grid/views/common-grid-wrapper.html',
                scope: {}
            };
        }]);