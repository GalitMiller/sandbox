angular.module('bricata.ui.severity')
    .factory("SeverityDataService",
    ["BricataUris", "CommonProxyForRequests", "SeverityItem",
        function (BricataUris, CommonProxyForRequests, SeverityItem) {
            return {

                getSeverity:function(sevId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SeverityItem.query({id: sevId}).$promise, true);
                },

                deleteSeverity:function(sevId){
                    var queryObject = {ids: sevId};

                    return CommonProxyForRequests.getDecoratedPromise(
                        SeverityItem.delete({q: JSON.stringify(queryObject)}).$promise, true);
                },

                editSeverity:function(editData) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SeverityItem.edit({id: editData.id}, editData).$promise, true);
                },

                createNewSeverity:function(newSev) {
                    return CommonProxyForRequests.getDecoratedPromise(
                        SeverityItem.create({id: ''}, newSev).$promise, true);
                }
            };

        }]);