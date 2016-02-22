angular.module("bricata.ui.policy")
    .factory("PolicyGridConfigurationService", [
        'BricataUris', 'CommonNavigationService', 'GridActionsHelper', 'PolicyDataService', 'gridCustomColumns',
        'gridStandardActions',
        function(BricataUris, CommonNavigationService, GridActionsHelper, PolicyDataService, gridCustomColumns,
                 gridStandardActions){

            var service = {
                getGridConfiguration:function(){

                    var config = {};
                    config.url = BricataUris.policyItems;

                    config.columns = [
                        {'field' : '', 'type': 'check', 'title': '', 'sortable': false, 'style': ''},
                        {'field' : 'name', 'type': 'text', 'title': 'policyGrid.nameCol', 'sortable': true,
                            'style': {'min-width': '220px', 'max-width': '220px'}},
                        {'field' : 'description', 'type': 'text', 'title': 'policyGrid.descCol', 'sortable': true,
                            'style': {'min-width': '230px', 'max-width': '230px'}},
                        {'field' : 'signatures_count', 'type': 'number', 'title': 'policyGrid.signaturesCol',
                            'sortable': true, 'style': {'min-width': '110px', 'max-width': '110px'}},
                        {'field' : 'last_applied_by', 'subfield': 'name', 'type': gridCustomColumns.dynamic,
                            'title': 'policyGrid.appliedCol', 'sortable': true,
                            'style': {'min-width': '140px', 'max-width': '140px'}
                        },
                        {'field' : 'created_at', 'type': gridCustomColumns.date, 'title': 'policyGrid.createdCol',
                            'sortable': true, 'style': {'min-width': '125px', 'max-width': '125px'}},
                        {'field' : 'created_by', 'subfield': 'name', 'type': 'text', 'title': 'policyGrid.authorCol',
                            'sortable': true, 'style': {'min-width': '140px', 'max-width': '140px'}},
                        {'field' : '', 'type': 'action', 'title': 'policyGrid.actionCol', 'sortable': false,
                            'style': {'min-width': '110px', 'max-width': '110px'},
                            'actions': [
                                {'label': 'policyGrid.actionClone', 'icon': 'glyphicon-duplicate',
                                    'actionName': 'policyClone', 'actionType': 'redirect'},
                                {'label': 'policyGrid.actionEdit', 'icon': 'glyphicon-pencil',
                                    'actionName': 'policyEdit', 'actionType': 'redirect'},
                                {'label': 'policyGrid.actionDelete', 'icon': 'glyphicon-remove',
                                    'actionName': 'policyDelete', 'actionType': 'modal', 'enableField': 'is_deletable'}
                            ]
                        }
                    ];

                    config.filters = {
                        searchFilter: {
                            fields: ['name', 'description']
                        },
                        /*optionFilter: {
                         field: 'is_applied',
                         options: [
                         { value: null, label: 'common.allTxt' },
                         { value: true, label: 'policyTypeFilter.appliedTxt' },
                         { value: false, label: 'policyTypeFilter.notAppliedTxt' }
                         ]
                         },*/
                        valueFilter: {
                            field: 'created_by_id',
                            data: {
                                url: BricataUris.policyGridFilterValues,
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
                        src: 'modules/policy/views/rowinfo/details/policy-grid-row-details-main.html'
                    };

                    config.labels = {
                        bulkDeletei18Lbl: 'policyGrid.deleteSelected',
                        loadFailed: "errors.policyGridDataError",
                        reloadBtn: "errors.reloadPolicies",
                        rowChangeInfo: {
                            delete: "policyDetails.deletedPolicyMsg",
                            deleteBulk: "policyDetails.deletedPolicyMsgBulk",
                            create: "policyDetails.createdPolicyMsg",
                            edit: "policyDetails.editedPolicyMsg",
                            change: "policyDetails.appliedPolicyMsg"
                        }
                    };

                    return config;
                },

                getActionModal:function(actionObject){
                    var modalConfiguration = {};
                    var processedAction = '';
                    switch (actionObject.actionName) {
                        case 'policyApply' :
                            modalConfiguration = {
                                templateUrl: 'modules/policyapply/views/apply-policy-modal.html',
                                controller: 'ApplyPolicyController',
                                windowClass: 'apply-policy-modal-window'
                            };
                            processedAction = gridStandardActions.change;
                            break;
                        case 'bulkDelete':
                        case 'policyDelete':
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
                                            bulkDeleteTitle: 'deletePolicyModal.deletePolicyTitleBulk',
                                            singleDeleteTitle: 'deletePolicyModal.deletePolicyTitle',
                                            bulkDeleteMsg: 'deletePolicyModal.deletePolicyMsgBulk',
                                            singleDeleteMsg: 'deletePolicyModal.deletePolicyMsg',
                                            errorTxt: 'errors.deletePolicyError'
                                        };
                                    },
                                    deleteMethod: function() {
                                        return PolicyDataService.deletePolicies;
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
                        case 'policyClone' :
                            GridActionsHelper.storeGridCloneData(actionObject.data[0]);
                            break;
                        case 'policyEdit':
                            GridActionsHelper.storeGridEditData(actionObject.data[0]);
                            break;
                    }

                    CommonNavigationService.navigateTo(BricataUris.pages.policyWizardPage, 'internal');
                }
            };
            return service;
        }]);