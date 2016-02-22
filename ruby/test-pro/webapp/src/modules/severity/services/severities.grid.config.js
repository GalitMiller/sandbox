angular.module("bricata.ui.severity")
    .factory("SeveritiesGridConfigurationService",
    ['BricataUris', 'SeverityDataService', 'GridActionsHelper', 'CommonNavigationService', 'gridStandardActions',
        'gridCustomColumns',
        function(BricataUris, SeverityDataService, GridActionsHelper, CommonNavigationService,
                 gridStandardActions, gridCustomColumns){

            var service = {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.severityList;

                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'severitiesGrid.nameFieldLbl', 'sortable': true,
                            'style': {'min-width': '210px', 'max-width': '210px'}},
                        {'field' : 'bg_color', 'type': 'text', 'title': 'severitiesGrid.bgFieldLbl',
                            'sortable': false, 'style': {'min-width': '90px', 'max-width': '90px'}},
                        {'field' : 'text_color', 'type': 'text', 'title': 'severitiesGrid.txtFieldLbl',
                            'sortable': false, 'style': {'min-width': '90px', 'max-width': '90px'}},
                        {'field' : 'severity', 'type': gridCustomColumns.severity,
                            'title': 'severitiesGrid.previewFieldLbl', 'sortable': false,
                            'style': {'min-width': '120px', 'max-width': '120px'}},
                        {'field' : 'weight', 'type': 'number', 'title': 'severitiesGrid.weightFieldLbl',
                            'sortable': true, 'style': {'min-width': '90px', 'max-width': '90px'}},
                        {'field' : 'signatures_count', 'type': 'number',
                            'title': 'severitiesGrid.signaturesCountFieldLbl',
                            'sortable': true, 'style': {'min-width': '100px', 'max-width': '100px'}},
                        {'field' : '', 'type': 'action', 'title': 'severitiesGrid.actionCol', 'sortable': false,
                            'style': {'min-width': '60px', 'max-width': '60px'},
                            'actions': [
                                {'label': 'severitiesGrid.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'severityEdit', 'actionType': 'redirect'},
                                {'label': 'severitiesGrid.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'severityDelete', 'actionType': 'modal',
                                    'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name']
                        }
                    };

                    config.defaultSorting = {field: 'name', direction: 'asc'};
                    config.createdSorting = {field: 'name', direction: 'asc'};

                    config.labels = {
                        bulkDeletei18Lbl: 'severitiesGrid.deleteSelected',
                        loadFailed: "errors.severitiesGridDataError",
                        reloadBtn: "errors.reloadSeverities",
                        rowChangeInfo: {
                            delete: "severitiesGrid.deletedSeverityMsg",
                            deleteBulk: "severitiesGrid.deletedSeverityMsgBulk",
                            create: "severitiesGrid.createdSeverityMsg",
                            edit: "severitiesGrid.editedSeverityMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'bulkDelete':
                        case 'severityDelete':
                            modalConfiguration = {
                                templateUrl: 'uicore/grid/views/delete-entity-modal.html',
                                controller: 'CommonDeleteEntityController',
                                size: 'sm',
                                resolve: {
                                    entityObjects: function(){
                                        return actionObject.data;
                                    },
                                    labels: function(){
                                        return {
                                            bulkDeleteTitle: 'deleteSeverityModal.deleteSeverityTitleBulk',
                                            singleDeleteTitle: 'deleteSeverityModal.deleteSeverityTitle',
                                            bulkDeleteMsg: 'deleteSeverityModal.deleteSeverityMsgBulk',
                                            singleDeleteMsg: 'deleteSeverityModal.deleteSeverityMsg',
                                            errorTxt: 'errors.deleteSeverityError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return SeverityDataService.deleteSeverity;
                                    }
                                }
                            };
                            processedAction = gridStandardActions.delete;
                            break;
                    }

                    return {config: modalConfiguration, action: processedAction};
                },

                performRedirect: function(actionObject) {
                    switch (actionObject.actionName) {
                        case 'severityEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateToSeverityWizardPage();
                }

            };
            return service;
        }]);