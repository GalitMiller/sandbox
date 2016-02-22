angular.module("bricata.ui.signatureclasstypes")
    .factory("SignatureClassTypesGridConfigurationService",
    ['BricataUris', 'CommonNavigationService', 'GridActionsHelper',
        'SignatureClassTypesDataService', 'gridStandardActions',
        function(BricataUris, CommonNavigationService, GridActionsHelper,
                 SignatureClassTypesDataService, gridStandardActions){

            return {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.signatureClassTypesGrid;


                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'signatureClassTypes.colName',
                            'sortable': true, 'style': {'min-width': '480px', 'max-width': '480px'}},
                        {'field' : 'short_name', 'type': 'text', 'title': 'signatureClassTypes.colShortName',
                            'sortable': true, 'style': {'min-width': '300px', 'max-width': '300px'}},
                        {'field' : 'priority', 'type': 'number', 'title': 'signatureClassTypes.colPriority',
                            'sortable': true, 'style': {'min-width': '80px', 'max-width': '80px'}},
                        {'field' : '', 'type': 'action', 'title': 'signatureClassTypes.actionCol', 'sortable': false,
                            'style': {'min-width': '50px', 'max-width': '50px'},
                            'actions': [
                                {'label': 'signatureClassTypes.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'signatureClassTypeEdit', 'actionType': 'redirect'},
                                {'label': 'signatureClassTypes.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'signatureClassTypeDelete', 'actionType': 'modal',
                                    'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name', 'short_name']
                        }
                    };

                    config.defaultSorting = {field: 'name', direction: 'asc'};
                    config.createdSorting = {field: 'name', direction: 'asc'};

                    config.labels = {
                        bulkDeletei18Lbl: 'signatureClassTypes.deleteSelected',
                        loadFailed: "errors.signatureClassTypesGridDataError",
                        reloadBtn: "errors.reloadSignatureClassTypes",
                        rowChangeInfo: {
                            delete: "signatureClassTypes.deletedSignatureClassTypesMsg",
                            deleteBulk: "signatureClassTypes.deletedSignatureClassTypesMsgBulk",
                            create: "createSignatureClassType.createdMsg",
                            edit: "createSignatureClassType.editedMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'classTypeImport':
                            modalConfiguration = {
                                templateUrl: 'modules/reporting/views/import.dialog.view.html',
                                controller: 'ImportDialogController',
                                resolve: {
                                    labels: function(){
                                        return {
                                            title: 'importClassType.title'
                                        };
                                    },
                                    importMethod: function(){
                                        return SignatureClassTypesDataService.uploadImportFile;
                                    }
                                }
                            };
                            processedAction = 'create';
                            break;
                        case 'bulkDelete':
                        case 'signatureClassTypeDelete':
                            modalConfiguration = {
                                templateUrl: 'uicore/grid/views/delete-entity-modal.html',
                                controller: 'CommonDeleteEntityController',
                                resolve: {
                                    entityObjects: function(){
                                        return actionObject.data;
                                    },
                                    labels: function(){
                                        return {
                                            bulkDeleteTitle: 'deleteSignatureClassTypesModal.deleteTitleBulk',
                                            singleDeleteTitle: 'deleteSignatureClassTypesModal.deleteTitle',
                                            bulkDeleteMsg: 'deleteSignatureClassTypesModal.deleteMsgBulk',
                                            singleDeleteMsg: 'deleteSignatureClassTypesModal.deleteMsg',
                                            errorTxt: 'errors.deleteSignatureClassTypesError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return SignatureClassTypesDataService.deleteSignatureClassTypeItem;
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
                        case 'signatureClassTypeEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateToSignatureClassTypeWizardPage();
                }
            };
        }]);