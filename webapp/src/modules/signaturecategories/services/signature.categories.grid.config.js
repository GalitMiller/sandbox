angular.module("bricata.ui.signaturecategories")
    .factory("SignatureCategoriesGridConfigurationService",
    ['BricataUris', 'CommonNavigationService', 'GridActionsHelper', 'SignatureCategoriesDataService',
        'gridStandardActions','gridCustomColumns',
        function(BricataUris, CommonNavigationService, GridActionsHelper, SignatureCategoriesDataService,
                 gridStandardActions, gridCustomColumns){

            return {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.signatureCategoriesList;


                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'signatureCategories.nameCol', 'sortable': true,
                            'style': {'min-width': '300px', 'max-width': '300px'}},
                        {'field' : 'description', 'type': 'text', 'title': 'signatureCategories.description',
                            'sortable': true, 'style': {'min-width': '560px', 'max-width': '560px'}},
                        {'field' : 'signatures_count', 'type': gridCustomColumns.dynamic,
                            'title': 'signatureCategories.signatures', 'sortable': true,
                            'style': {'min-width': '100px', 'max-width': '100px'}
                        },
                        {'field' : '', 'type': 'action', 'title': 'signatureCategories.actionCol', 'sortable': false,
                            'style': {'min-width': '50px', 'max-width': '50px'},
                            'actions': [
                                {'label': 'signatureCategories.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'signatureEdit', 'actionType': 'redirect'},
                                {'label': 'signatureCategories.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'signatureDelete', 'actionType': 'modal',
                                    'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name', 'description']
                        }
                    };

                    config.defaultSorting = {field: 'name', direction: 'asc'};
                    config.createdSorting = {field: 'name', direction: 'asc'};

                    config.rowDetailsView = {
                        src: 'modules/signaturecategories/views/rowinfo/signature-category-grid-row-details-main.html'
                    };

                    config.labels = {
                        bulkDeletei18Lbl: 'signatureCategories.deleteSelected',
                        loadFailed: "errors.signaturesGridDataError",
                        reloadBtn: "errors.reloadSignatures",
                        rowChangeInfo: {
                            delete: "createSignatureCategory.deletedSignatureCategoryMsg",
                            deleteBulk: "createSignatureCategory.deletedSignatureCategoryMsgBulk",
                            create: "createSignatureCategory.createdSignatureCategoryMsg",
                            edit: "createSignatureCategory.editedSignatureCategoryMsg",
                            change: "createSignatureCategory.editedSignatureCategoryMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject) {
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'addNewSignature' :
                        modalConfiguration = {
                            templateUrl: 'modules/signature/views/newsignature/add-new-signature-modal.html',
                            windowClass: 'new-signature-modal-window',
                            controller: 'NewSignatureModalController',
                            resolve: {
                                categoryId: function(){
                                    return actionObject.data[0].id;
                                }
                            }
                        };
                        break;
                        case 'importSignatures' :
                            modalConfiguration = {
                                templateUrl: 'modules/signature/views/import/import-signature-modal.html',
                                controller: 'ImportSignatureController',
                                resolve: {
                                    selectedCategory: function(){
                                        return actionObject.data[0];
                                    }
                                }
                            };
                            processedAction = gridStandardActions.change;
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
                                            bulkDeleteTitle: 'deleteSignatureCategoryModal.deleteSignatureCatTitleBulk',
                                            singleDeleteTitle: 'deleteSignatureCategoryModal.deleteSignatureCatTitle',
                                            bulkDeleteMsg: 'deleteSignatureCategoryModal.deleteSignatureCatMsgBulk',
                                            singleDeleteMsg: 'deleteSignatureCategoryModal.deleteSignatureCatMsg',
                                            errorTxt: 'errors.deleteSignatureCategoryError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return SignatureCategoriesDataService.deleteSignatureCategoriesItem;
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
                        case 'signatureEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateToSignatureCategoriesWizardPage();
                }
            };
        }]);