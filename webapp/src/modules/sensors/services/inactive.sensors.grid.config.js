angular.module("bricata.ui.sensors")
    .factory("InactiveSensorsGridConfigurationService", ['BricataUris', 'gridStandardActions',
        function(BricataUris, gridStandardActions){

            var service = {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.inactiveSensorItems;

                    config.columns = [
                        {'field' : 'name', 'type': 'text', 'title': 'inactiveSensorGrid.nameCol', 'sortable': true,
                            'style': {'min-width': '400px', 'max-width': '400px'}},
                        {'field' : 'hostname', 'type': 'number', 'title': 'inactiveSensorGrid.hostnameCol',
                            'sortable': true, 'style': {'min-width': '350px', 'max-width': '350px'}},
                        {'field' : '', 'type': 'action', 'title': 'inactiveSensorGrid.actionCol', 'sortable': false,
                            'style': {'min-width': '110px', 'max-width': '110px'},
                            'actions': [
                                {'label': 'inactiveSensorGrid.actionActivate', 'icon': 'glyphicon-play',
                                    'actionName': 'showActivation', 'actionType': 'modal'}
                            ]
                        }
                    ];

                    /*config.filters = {
                        searchFilter: {
                            fields: ['name', 'hostname']
                        }
                    };*/

                    config.defaultSorting = {field: 'name', direction: 'asc'};

                    config.labels = {
                        loadFailed: "errors.inactiveSensorsGridDataError",
                        reloadBtn: "errors.reloadInactiveSensors",
                        rowChangeInfo: {
                            delete: "inactiveSensorGrid.activationSuccessMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'showActivation' :
                            modalConfiguration = {
                                templateUrl: 'modules/sensors/views/sensor-activate-modal.html',
                                controller: 'ActivateSensorController',
                                windowClass: 'sensor-activate-modal-window',
                                resolve: {
                                    inactiveSensor: function () {
                                        return actionObject.data[0];
                                    }
                                }
                            };
                            processedAction = gridStandardActions.delete;
                            break;
                    }

                    return {config: modalConfiguration, action: processedAction};
                }

            };
            return service;
        }]);