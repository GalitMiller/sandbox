angular.module("bricata.ui.signature")
    .factory("SignaturesGridConfigurationService",
    ['BricataUris', 'CommonNavigationService', 'GridActionsHelper', 'SignatureDataService', 'gridCustomColumns',
        'gridStandardActions',
        function(BricataUris, CommonNavigationService, GridActionsHelper, SignatureDataService, gridCustomColumns,
                 gridStandardActions){

            return {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.signaturesList;

                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'signaturesGrid.nameCol', 'sortable': true,
                            'style': {'min-width': '370px', 'max-width': '370px'}},
                        {'field' : 'sid', 'type': 'number', 'title': 'signaturesGrid.SIDCol', 'sortable': true,
                            'style': {'min-width': '100px', 'max-width': '100px'}},
                        {'field' : 'severity', 'subfield' : 'weight', 'type': gridCustomColumns.severity,
                            'title': 'signaturesGrid.severityCol', 'class': 'signature-grid-severities',
                            'sortable': true, 'style': {'min-width': '90px', 'max-width': '120px'},
                            'values': [
                                {'match': 'null',   'value': 'signatureLbl.label_0', class: 'signatureLbl.label_0'},
                                {'match': 'high',   'value': 'signatureLbl.label_1', class: 'signatureLbl.label_1'},
                                {'match': 'medium', 'value': 'signatureLbl.label_2', class: 'signatureLbl.label_2'},
                                {'match': 'low',    'value': 'signatureLbl.label_3', class: 'signatureLbl.label_3'}
                            ]
                        },
                        {'field' : 'action', 'type': 'text', 'title': 'signaturesGrid.signatureActionCol',
                            'sortable': true, 'style': {'min-width': '110px', 'max-width': '110px'}},
                        {'field' : 'created_at', 'type': gridCustomColumns.date,
                            'title': 'signaturesGrid.dateCreatedCol',
                            'sortable': true, 'style': {'min-width': '125px', 'max-width': '125px'}},
                        {'field' : 'created_by', 'subfield': 'name', 'type': 'text',
                            'title': 'signaturesGrid.createdByCol', 'sortable': true,
                            'style': {'min-width': '140px', 'max-width': '140px'}},
                        {'field' : '', 'type': 'action', 'title': 'signaturesGrid.actionCol', 'sortable': false,
                            'style': {'min-width': '90px', 'max-width': '90px'},
                            'actions': [
                                {'label': 'signaturesGrid.actionClone', 'icon': 'glyphicon-duplicate',
                                    'actionName': 'signatureClone', 'actionType': 'redirect'},
                                {'label': 'signaturesGrid.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'signatureEdit', 'actionType': 'redirect',
                                    'enableField': 'is_editable'},
                                {'label': 'signaturesGrid.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'signatureDelete', 'actionType': 'modal',
                                    'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name', 'sid']
                        },
                        valueFilter: {
                            field: 'created_by_id',
                            data: {
                                url: BricataUris.signaturesGridFilterValues,
                                labelField: "name",
                                valueField: "id"
                            }
                        },
                        dateFilter: {
                            field: 'created_at'
                        }
                    };

                    config.defaultSorting = {field: 'name', direction: 'asc'};
                    config.createdSorting = {field: 'created_at', direction: 'desc'};

                    config.rowDetailsView = {
                        src: 'modules/signature/views/rowinfo/details/signatures-grid-row-details-main.html'
                    };

                    config.labels = {
                        bulkDeletei18Lbl: 'signaturesGrid.deleteSelected',
                        loadFailed: "errors.signaturesGridDataError",
                        reloadBtn: "errors.reloadSignatures",
                        rowChangeInfo: {
                            delete: "signatureDetails.deletedSignatureMsg",
                            deleteBulk: "signatureDetails.deletedSignatureMsgBulk",
                            create: "signatureDetails.createdSignatureMsg",
                            edit: "signatureDetails.editedSignatureMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'signatureImport':
                            modalConfiguration = {
                                templateUrl: 'modules/signature/views/import/import-signature-modal.html',
                                controller: 'ImportSignatureController',
                                resolve: {
                                    selectedCategory: null
                                }
                            };
                            processedAction = 'create';
                            break;
                        case 'bulkDelete':
                        case 'signatureDelete':
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
                                            bulkDeleteTitle: 'deleteSignatureModal.deleteSignatureTitleBulk',
                                            singleDeleteTitle: 'deleteSignatureModal.deleteSignatureTitle',
                                            bulkDeleteMsg: 'deleteSignatureModal.deleteSignatureMsgBulk',
                                            singleDeleteMsg: 'deleteSignatureModal.deleteSignatureMsg',
                                            errorTxt: 'errors.deleteSignatureError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return SignatureDataService.deleteSignature;
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
                        case 'signatureClone' :
                            GridActionsHelper.storeGridCloneData(actionObject.data[0]);
                            break;
                        case 'signatureEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateToSignatureWizardPage();
                }

            };
        }]);