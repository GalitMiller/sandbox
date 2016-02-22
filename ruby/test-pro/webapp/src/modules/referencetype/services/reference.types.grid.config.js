angular.module("bricata.ui.referencetype")
    .factory("ReferenceTypesGridConfigurationService",
    ['BricataUris', 'ReferenceTypeDataService', 'GridActionsHelper', 'CommonNavigationService', 'gridStandardActions',
        function(BricataUris, ReferenceTypeDataService, GridActionsHelper, CommonNavigationService,
                 gridStandardActions){

            var service = {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.referenceTypeList;

                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'referenceTypesGrid.nameFieldLbl', 'sortable': true,
                            'style': {'min-width': '350px', 'max-width': '350px'}},
                        {'field' : 'url_prefix', 'type': 'text', 'title': 'referenceTypesGrid.urlFieldName',
                            'sortable': true, 'style': {'min-width': '350px', 'max-width': '350px'}},
                        {'field' : '', 'type': 'action', 'title': 'referenceTypesGrid.actionCol', 'sortable': false,
                            'style': {'min-width': '60px', 'max-width': '60px'},
                            'actions': [
                                {'label': 'referenceTypesGrid.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'referenceEdit', 'actionType': 'redirect'},
                                {'label': 'referenceTypesGrid.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'referenceDelete', 'actionType': 'modal',
                                    'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name', 'url_prefix']
                        }
                    };

                    config.defaultSorting = {field: 'name', direction: 'asc'};
                    config.createdSorting = {field: 'name', direction: 'asc'};

                    config.labels = {
                        bulkDeletei18Lbl: 'referenceTypesGrid.deleteSelected',
                        loadFailed: "errors.referenceTypesGridDataError",
                        reloadBtn: "errors.reloadReferenceTypes",
                        rowChangeInfo: {
                            delete: "referenceTypesGrid.deletedReferenceMsg",
                            deleteBulk: "referenceTypesGrid.deletedReferenceMsgBulk",
                            create: "referenceTypesGrid.createdReferenceMsg",
                            edit: "referenceTypesGrid.editedReferenceMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'referenceImport':
                            modalConfiguration = {
                                templateUrl: 'modules/reporting/views/import.dialog.view.html',
                                controller: 'ImportDialogController',
                                resolve: {
                                    labels: function(){
                                        return {
                                            title: 'importReferenceType.title'
                                        };
                                    },
                                    importMethod: function(){
                                        return ReferenceTypeDataService.uploadImportFile;
                                    }
                                }
                            };
                            processedAction = 'create';
                            break;
                        case 'bulkDelete':
                        case 'referenceDelete':
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
                                            bulkDeleteTitle: 'deleteReferenceModal.deleteReferenceTitleBulk',
                                            singleDeleteTitle: 'deleteReferenceModal.deleteReferenceTitle',
                                            bulkDeleteMsg: 'deleteReferenceModal.deleteReferenceMsgBulk',
                                            singleDeleteMsg: 'deleteReferenceModal.deleteReferenceMsg',
                                            errorTxt: 'errors.deleteReferenceError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return ReferenceTypeDataService.deleteReferenceType;
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
                        case 'referenceEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateToReferenceTypeWizardPage();
                }

            };
            return service;
        }]);