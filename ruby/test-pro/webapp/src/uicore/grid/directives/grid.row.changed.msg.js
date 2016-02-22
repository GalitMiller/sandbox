angular.module("bricata.uicore.grid")
    .directive("gridRowChangedMsg", [
        function() {
            return {
                restrict : 'E',
                templateUrl : 'uicore/grid/views/grid-row-changed-content.html',
                scope: {
                    changedObject: "=",
                    deleteMsg: '@',
                    deleteBulkMsg: '@',
                    createMsg: '@',
                    editMsg: '@',
                    changeMsg: '@'
                }
            };
        }]);