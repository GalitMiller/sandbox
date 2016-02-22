angular.module('bricata.uicore.grid')
    .controller('GridCommonControl',
    ['$scope', 'GridConfiguration', 'CommonModalService', 'BroadcastService',
    function($scope, GridConfiguration, CommonModalService, BroadcastService) {
        $scope.reportId = GridConfiguration.getReportId();
        $scope.configuration = GridConfiguration.getConfiguration($scope.reportId);

        $scope.lastGridAction = '';

        $scope.gridRowAction = function(actionObject) {
            $scope.changedObject = {};
            switch (actionObject.actionType) {
                case 'modal':
                    var modalData = GridConfiguration.getModal($scope.reportId, actionObject);
                    $scope.lastGridAction = modalData.action;
                    CommonModalService.show(modalData.config).then(function (modalData) {
                        $scope.changedObject = {data: modalData, action: $scope.lastGridAction};
                    });
                    break;
                case 'redirect':
                    GridConfiguration.redirectToPage($scope.reportId, actionObject);
                    break;

            }
        };

        $scope.$on('grid.header.invoke.row.action', function(event, data) {
            $scope.gridRowAction(data);
        });

        $scope.topLvlMsg = BroadcastService.messageObject;

        $scope.handleTopLvlMsgChange = function(isGetLatest) {
            var eventData = isGetLatest ? BroadcastService.messageObject : $scope.topLvlMsg;

            if (eventData) {
                $scope.changedObject = {};
                if (eventData.action.length > 0) {
                    $scope.changedObject = {data: eventData, action: eventData.action};
                    BroadcastService.consumeMsg();
                }
            }
        };

        $scope.$watch('topLvlMsg', function() {
            $scope.handleTopLvlMsgChange();
        }, true);

        $scope.$on('top.lvl.msg', function() {
            $scope.handleTopLvlMsgChange(true);
        });

    }]);
