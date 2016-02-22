angular.module("bricata.uicore.grid")
    .factory("GridActionsHelper",[function(){
            var gridCloneData;
            var gridEditData;

            var service = {
                storeGridCloneData:function(cloneData) {
                    gridCloneData = cloneData;
                },
                getGridCloneData:function() {
                    return gridCloneData;
                },
                consumeGridCloneData:function() {
                    gridCloneData = undefined;
                },
                storeGridEditData:function(editData) {
                    gridEditData = editData;
                },
                getGridEditData:function() {
                    return gridEditData;
                },
                consumeGridEditData:function() {
                    gridEditData = undefined;
                }
            };
            return service;
        }]);