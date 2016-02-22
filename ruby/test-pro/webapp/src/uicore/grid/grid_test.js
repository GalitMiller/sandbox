describe('bricata core ui grid', function() {

    var $controller,
        $rootScope,
        $compile,
        $httpBackend,
        element,
        gridConfig,
        isRedirectCalled,
        BroadcastService,
        GridConfiguration,
        GridActionsHelper,
        GridCommonService,
        filterDataTop;

    beforeEach(module('bricata.uicore', function(_GridConfigurationProvider_, $provide) {
        isRedirectCalled = false;

        gridConfig = _GridConfigurationProvider_;
        gridConfig.setReportIdMethod(function(){return 'test'});
        gridConfig.setConfigProvider(function(){
            return {
                getGridConfiguration: function() {
                    return {};
                },
                performRedirect: function(actionObject) {
                    isRedirectCalled = true;
                }
            };
        });
        gridConfig.setGridRequestUrl('fake/:entityId');
        gridConfig.setFilterRequestUrl('fake/:entityId');

        gridConfig.setGridPageSizes(function(){return [10]});

        gridConfig.setRangeDetectMethod(function(type) {
            var ranges = {};


            switch (type) {
                case 'severity' :
                    ranges =  [
                        {"minValue": 1, "maxValue": 75, "priority": 1, "levelName": "high"}
                    ];
                    break;
            }

            return ranges;
        });
    }));

    beforeEach(inject(function(_$controller_, _$rootScope_, _$compile_, _$httpBackend_, _BroadcastService_,
                               _GridConfiguration_, _GridActionsHelper_, _GridCommonService_){
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $compile = _$compile_;
        $httpBackend = _$httpBackend_;
        BroadcastService = _BroadcastService_
        GridConfiguration = _GridConfiguration_;
        GridActionsHelper = _GridActionsHelper_;
        GridCommonService = _GridCommonService_;
    }));

    describe('GridCommonControl methods', function() {
        var $scope;

        beforeEach(function() {
            $scope = $rootScope;

            $scope.reportId = 'test';
            $scope.gridRowAction = function(){};
            $scope.changedObject = {};

            element = angular.element('<common-grid-wrapper></common-grid-wrapper>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check grid handles row action', function() {
            var eventData = {
                actionName: "test",
                actionType: "redirect",
                data: []
            };

            $scope.$broadcast('grid.header.invoke.row.action', eventData);

            expect(isRedirectCalled).toBeTruthy();
        });

        it('check top level message consumed', function() {
            BroadcastService.changeTopLevelMessage({action: 'test'});

            $scope.$broadcast('top.lvl.msg');

            expect(BroadcastService.messageObject).toBe(undefined);
        });

    });

    describe('GridController methods', function() {
        var $scope, controller;

        beforeEach(function() {
            GridConfiguration.savePageNumber('testId', 15);

            $scope = $rootScope;

            $scope.reportId = 'testId';
            $scope.pagination = {
                currentPage: 5
            };
            $scope.tableParams = {
                reload: function () {
                },
                sorting: function(columnField,sortDirection){},
                isSortBy: function(field, direction){return false;}
            };
            $scope.pageSize = {
                options: [10],
                selection: 50
            };
            $scope.sorting = {};

            $scope.gridConfiguration = {
                defaultSorting: {field: 'name', direction: 'asc'},
                createdSorting: {field: 'created_at', direction: 'desc'},
                rowDetailsView: {src: 'test'}
            };

            controller = $controller('GridController', { $scope: $scope });
        });

        it('check filter clean method', function() {
            spyOn($scope, "reloadGridData");
            $scope.filterChanged('some filter value');
            expect($scope.reloadGridData).toHaveBeenCalled();
            expect($scope.pagination.currentPage).toEqual(1);
        });


        it('check resetGridOptions method', function() {
            $scope.filterData = ['test'];

            $scope.resetGridOptions();

            expect($scope.filterData.length).toEqual(0);
            expect($scope.pagination.currentPage).toEqual(1);
            expect($scope.pageSize.selection).toEqual(10);
            expect(GridConfiguration.getPageNumber('testId')).toEqual(-1);
        });

        it('check sortTable method', function() {
            spyOn($scope, "clearRowStatus");
            spyOn($scope, "clearCheckBoxSelections");

            $scope.sortTable('testColumn', 'testDirection');

            expect($scope.clearRowStatus).toHaveBeenCalled();
            expect($scope.clearCheckBoxSelections).toHaveBeenCalled();
            expect($scope.sorting.field).toEqual('testColumn');
            expect($scope.sorting.direction).toEqual('testDirection');
            expect(GridConfiguration.getSorting('testId').field).toEqual('testColumn');
            expect(GridConfiguration.getSorting('testId').direction).toEqual('testDirection');
        });

        it('check changePageSize method', function() {
            spyOn($scope, "reloadGridData");

            $scope.changePageSize(50);

            expect($scope.reloadGridData).toHaveBeenCalled();
            expect($scope.pagination.currentPage).toEqual(1);
            expect($scope.pageSize.selection).toEqual(50);
            expect(GridConfiguration.getPageNumber('testId')).toEqual(1);
            expect(GridConfiguration.getPageSize('testId')).toEqual(50);
        });

        it('check rowAction method', function() {
            var injectedRowActionHandlerCalled = false;
            $scope.rowActionHandler = function(){
                return function(obj) {
                    injectedRowActionHandlerCalled = true;
                }
            };

            $scope.bulkDeleteHandler();

            expect(injectedRowActionHandlerCalled).toBeTruthy();

            spyOn($scope, "handleRowClick");
            $scope.rowAction(null, 'rowdetail', [0], {stopImmediatePropagation: function(){}});
            expect($scope.handleRowClick).toHaveBeenCalled();
        });

        it('check reloadDataAfterError method', function() {
            $scope.sortTable('testColumn', 'testDirection');
            $scope.states = {
                dataLoadErrorOccured: true
            };
            spyOn($scope, "resetGridOptions");
            spyOn($scope, "reloadGridData");

            $scope.reloadDataAfterError();

            expect($scope.resetGridOptions).toHaveBeenCalled();
            expect($scope.reloadGridData).toHaveBeenCalled();
            expect($scope.states.dataLoadErrorOccured).toBeFalsy();
            expect($scope.sorting.field).toEqual('name');
            expect($scope.sorting.direction).toEqual('asc');
        });

        it('check handleDeleteStatus method', function() {
            spyOn($scope, "reloadGridData");

            $scope.handleDeleteStatus();

            expect($scope.reloadGridData).toHaveBeenCalled();
        });

        it('check handleEditStatus  method', function() {
            spyOn($scope, "reloadGridData");

            $scope.handleEditStatus();

            expect($scope.reloadGridData).toHaveBeenCalled();
        });

        it('check handleCreateStatus  method', function() {
            $scope.sortTable('testColumn', 'testDirection');
            spyOn($scope, "resetGridOptions");

            $scope.handleCreateStatus();

            expect($scope.resetGridOptions).toHaveBeenCalled();
            expect($scope.sorting.field).toEqual('created_at');
            expect($scope.sorting.direction).toEqual('desc');
        });

        it('check handleNewDataLoaded  method', function() {
            spyOn($scope, "updateTopLevelTotal");
            spyOn($scope, "checkFilterReturnedData");
            spyOn($scope, "markChangedRow");

            $scope.handleNewDataLoaded(12, 4, 3, []);

            expect($scope.updateTopLevelTotal).toHaveBeenCalled();
            expect($scope.checkFilterReturnedData).toHaveBeenCalled();
            expect($scope.markChangedRow).toHaveBeenCalled();
            expect($scope.pagination.loadedItemsCount).toBe(4);
            expect($scope.pagination.currentPage).toBe(3);
            expect(GridConfiguration.getPageNumber('testId')).toEqual(3);
        });

        it('check markChangedRow  method', function() {
            var data = [{id: 0}, {id: 1}];

            $scope.changedObject = {data: {id: 1, field: 'testField', value: 'testValue'}};
            $scope.markChangedRow(data);

            expect(data[1].isChanged).toBeTruthy();
            expect(data[1].testField).toBe('testValue');

            $scope.changedObject = {data: {id: -1}};
            $scope.markChangedRow(data);
            expect(data[0].isChanged).toBeFalsy();
            expect(data[1].isChanged).toBeFalsy();

            data = [{id: 0}, {id: 1}];
            $scope.changedObject = {data: {bulkChangeIds: [0, 1], field: 'testField', value: 'testValue'}};
            $scope.markChangedRow(data);
            expect(data[0].testField).toBe('testValue');
            expect(data[1].testField).toBe('testValue');
        });

        it('check handleRowClick method', function() {
            var clickedEntity = {id: 1};
            $scope.tableParams.data = [{id: 0, $selected: true}, {id: 1, $selected: true}];

            $scope.states.isRowSelectionEnabled = true;

            $scope.handleRowClick(clickedEntity, 'check');

            expect($scope.tableParams.data[0].$selected).toBeTruthy();
            expect($scope.tableParams.data[1].$selected).toBeTruthy();

            $scope.handleRowClick(clickedEntity, 'action');

            expect($scope.tableParams.data[0].$selected).toBeFalsy();
            expect($scope.tableParams.data[1].$selected).toBeFalsy();

            $scope.handleRowClick(clickedEntity, '');

            expect($scope.tableParams.data[0].$selected).toBeFalsy();
            expect($scope.tableParams.data[1].$selected).toBeTruthy();

            $scope.handleRowClick(clickedEntity, '');

            expect($scope.tableParams.data[0].$selected).toBeFalsy();
            expect($scope.tableParams.data[1].$selected).toBeFalsy();
        });
    });

    describe('commonGrid directive', function() {
        var $scope;

        beforeEach(function() {
            $httpBackend.when('GET', 'assets/images/preloader.svg').respond({});

            $httpBackend.whenGET(function(url) {
                return url.indexOf("fake/test%") === 0;
            }).respond(
                {
                    "objects": [
                        {
                            "id": 0,
                            "name": "test name",
                            "author": {
                                "name": "John"
                            },
                            "time": "2015-03-10T14:28:01.263362",
                            "severity": {
                                "weight": 10
                            },
                            "count": 1,
                            "checked": true
                        },
                        {
                            "id": 1,
                            "severity": {
                                "weight": null
                            },
                            "checked": false
                        }
                    ]
                }
            );

            $scope = $rootScope;
            $scope.reportId = 'test';
            $scope.configuration = {
                url: 'test/request',
                columns: [
                    {'field' : 'name', 'type': 'text'},
                    {'field' : 'author', 'subfield': 'name'},
                    {'field' : 'time', 'type': 'date'},
                    {'field': 'severity', 'subfield': 'weight', 'type': 'range',
                        'values': [
                            {'match': 'null', 'value': 'null_value', class: 'null_class'},
                            {'match': 'high', 'value': 'high_value', class: 'high_class'}
                        ]
                    },
                    {'field' : 'count', 'type': 'dynamic'},
                    {'field' : 'checked', 'type': 'dynamicValue',
                        'values': [
                            {'match': true, 'value': 'true_value'},
                            {'match': false, 'value': 'false_value'}
                        ]
                    }
                ],
                defaultSorting: {field: 'name', direction: 'asc'},
                labels: {
                    bulkDeletei18Lbl: 'bulk_delete_test'
                }
            };
            $scope.gridRowAction = function(){};
            $scope.changedObject = {};

            element = angular.element('<common-grid report-id="reportId" ' +
                'grid-configuration="configuration" ' +
                'row-action-handler="gridRowAction" ' +
                'changed-object="changedObject"></common-grid>');

            $compile(element)($scope);
            $httpBackend.flush();
            $scope.$digest();
        });

        it('check grid initialization', function() {
            var isolated = element.isolateScope();

            expect(isolated.isGridInited).toBeTruthy();
            expect(isolated.columnDefinitions.length).toEqual(6);
            expect(isolated.bulkDeleteAvailable).toBeTruthy();
            expect(isolated.sorting.field).toBe('name');
            expect(isolated.sorting.direction).toBe('asc');
            expect(isolated.tableParams).not.toBe(null);
            expect(isolated.checkboxes.checked).toBeFalsy();
            expect(isolated.checkboxes.items).not.toBe(null);
        });

        it('check grid processing data', function() {
            var isolated = element.isolateScope();

            expect(isolated.tableParams.settings().$scope.$data.length).toBe(2);

            expect(isolated.tableParams.settings().$scope.$data[0].name).toBe('test name');
            expect(isolated.tableParams.settings().$scope.$data[0].author.name).toBe('John');
            expect(isolated.tableParams.settings().$scope.$data[0].time).not.toBe('-');
            expect(isolated.tableParams.settings().$scope.$data[0].severity.weight.value).toBe('high_value');
            expect(isolated.tableParams.settings().$scope.$data[0].severity.weight.class).toBe('high_class');
            expect(isolated.tableParams.settings().$scope.$data[0].count).toBe(1);
            expect(isolated.tableParams.settings().$scope.$data[0].checked).toBe('true_value');

            expect(isolated.tableParams.settings().$scope.$data[1].name).toBe('-');
            expect(isolated.tableParams.settings().$scope.$data[1].author.name).toBe('-');
            expect(isolated.tableParams.settings().$scope.$data[1].time).toBe('-');
            expect(isolated.tableParams.settings().$scope.$data[1].severity.weight.value).toBe('null_value');
            expect(isolated.tableParams.settings().$scope.$data[1].severity.weight.class).toBe('null_class');
            expect(isolated.tableParams.settings().$scope.$data[1].count).toBe('-');
            expect(isolated.tableParams.settings().$scope.$data[1].checked).toBe('false_value');
        });
    });

    describe('GridActionsHelper methods', function() {
        it('check GridActionsHelper methods', function() {

            var testData = {id: 1};

            GridActionsHelper.storeGridCloneData(testData);
            expect(GridActionsHelper.getGridCloneData().id).toBe(1);
            GridActionsHelper.consumeGridCloneData();
            expect(GridActionsHelper.getGridCloneData()).toBe(undefined);

            GridActionsHelper.storeGridEditData(testData);
            expect(GridActionsHelper.getGridEditData().id).toBe(1);
            GridActionsHelper.consumeGridEditData();
            expect(GridActionsHelper.getGridEditData()).toBe(undefined);
        });
    });

    describe('commonFilter directive', function() {
        var $scope, controller;
        filterDataTop = [];

        beforeEach(function() {
            $scope = $rootScope;
            $scope.reportId = 'test';
            $scope.showWeeksOnDatePicker = false;

            $httpBackend.when('GET', 'fake/value_filter.json?results_per_page=1000').respond({
                "objects": [
                    {
                        "id": 1,
                        "name": "John Doe"
                    }
                ]
            });

            $scope.gridConfiguration = {
                filters: {
                    searchFilter: {
                        fields: ['name']
                    },
                    optionFilter: {
                        field: 'is_applied',
                        options: [
                            { value: null, label: 'common.allTxt' },
                            { value: true, label: 'policyTypeFilter.appliedTxt' },
                            { value: false, label: 'policyTypeFilter.notAppliedTxt' }
                        ]
                    },
                    dateFilter: {
                        field: 'created_at'
                    },
                    valueFilter: {
                        field: 'author_id',
                        data: {
                            url: 'value_filter.json',
                            labelField: "name",
                            valueField: "id"
                        }
                    }
                }
            };
            $scope.filterChanged = function(filterData){
                filterDataTop = filterData;
            };

            element = angular.element('<div common-filter filter-config="gridConfiguration.filters" ' +
                'filter-changed="filterChanged" report-id="reportId" ' +
                'date-picker-show-weeks="showWeeksOnDatePicker"></div>');

            $compile(element)($scope);
            $httpBackend.flush();
            $scope.$digest();
        });

        it('check filter initialization', function() {
            var isolated = element.isolateScope();

            expect(isolated.filterConfigExists).toBeTruthy();
            expect(isolated.states.isSearchFilterInited).toBeTruthy();
            expect(isolated.states.isOptionFilterReady).toBeTruthy();
            expect(isolated.states.isDateFilterInited).toBeTruthy();
            expect(isolated.states.isValueFilterInited).toBeTruthy();
        });

        it('check filtering mechanism', function() {
            var isolated = element.isolateScope();
            var currentDate = new Date();

            isolated.selectedFilters['searchFilterVal'] = 'test name';
            isolated.selectedFilters['optionFilterVal'] = isolated.optionFilterValues[1];
            isolated.selectedFilters['valueFilterVal'] = isolated.valueFilterValues[1];
            isolated.selectedFilters['dateStart'] = currentDate;
            isolated.selectedFilters['dateEnd'] = currentDate;
            isolated.processFilterChange();

            expect(filterDataTop.length).toBe(5);

            expect(filterDataTop[0].or[0].name).toBe('name');
            expect(filterDataTop[0].or[0].val).toBe('%test name%');

            expect(filterDataTop[1].name).toBe('is_applied');
            expect(filterDataTop[1].val).toBeTruthy();

            expect(filterDataTop[2].name).toBe('author_id');
            expect(filterDataTop[2].val).toBe(1);

            expect(filterDataTop[3].name).toBe('created_at');
            expect(filterDataTop[3].val).not.toBe(null);

            expect(filterDataTop[4].name).toBe('created_at');
            expect(filterDataTop[4].val).not.toBe(null);

            expect(isolated.clearFilterState).toBe('active');

            isolated.clearFilter();
            isolated.processFilterChange();
            expect(filterDataTop.length).toBe(0);
            expect(isolated.clearFilterState).toBe('disabled');
        });
    });
});