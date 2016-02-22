angular.module("bricata.uicore.grid")
    .directive("commonGrid", ['$i18next', 'GridCommonService', 'ngTableParams',
        'GridConfiguration', 'gridStandardActions',
        function($i18next, GridCommonService, ngTableParams, GridConfiguration,
                 gridStandardActions) {
        return {
            restrict : 'EA',
            templateUrl : 'uicore/grid/views/common-grid.html',
            controller: 'GridController',
            scope: {
                reportId: "=",
                gridConfiguration: "=",
                changedObject: "=",
                rowActionHandler: "&"
            },
            link: function(scope) {
                scope.data = GridCommonService.data;
                scope.columnDefinitions = null;
                scope.gridOptions = {columnDefs: scope.columnDefinitions};
                scope.rowChangedObject = null;

                scope.isGridInited = false;
                scope.dateFormat = $i18next('formats.gridDateFormat');
                scope.showWeeksOnDatePicker = $i18next('formats.showWeekNumbers') ? true : false;

                scope.selectAllProp = undefined;

                scope.bulkDeleteAvailable = false;
                scope.bulkDeleteLbl = '';
                scope.bulkDeleteDisabled = true;

                scope.isRowClickDisabled = false;

                var unbindConfigWatcher = scope.$watch('gridConfiguration', function() {
                    if (angular.isDefined(scope.gridConfiguration.columns)) {
                        scope.isRowClickDisabled = !angular.isDefined(scope.gridConfiguration.rowDetailsView) ||
                            !angular.isDefined(scope.gridConfiguration.rowDetailsView.src);

                        scope.columnDefinitions = scope.gridConfiguration.columns;

                        scope.initializeGrid();

                        scope.isGridInited = true;

                        if (angular.isDefined(scope.gridConfiguration.labels.bulkDeletei18Lbl)) {
                            scope.bulkDeleteLbl = scope.gridConfiguration.labels.bulkDeletei18Lbl;
                            scope.bulkDeleteAvailable = true;
                        }
                    }

                    unbindConfigWatcher();
                });

                scope.$watch('changedObject', function() {
                    if (scope.changedObject && scope.changedObject.action) {
                        switch (scope.changedObject.action) {
                            case gridStandardActions.change:
                                scope.markChangedRow();
                                break;
                            case gridStandardActions.edit:
                                scope.handleEditStatus();
                                break;
                            case gridStandardActions.delete:
                                scope.handleDeleteStatus();
                                break;
                            case gridStandardActions.create:
                                scope.handleCreateStatus();
                                break;
                        }
                    }
                });

                scope.initializeGrid = function() {
                    var savedSorting = GridConfiguration.getSorting(scope.reportId);
                    scope.sorting = angular.copy(savedSorting ? savedSorting : scope.gridConfiguration.defaultSorting);

                    scope.pageSize = {};
                    scope.pageSize.options = GridConfiguration.getGridPageSizes();
                    var savedPageSize = GridConfiguration.getPageSize(scope.reportId);
                    scope.pageSize.selection = savedPageSize.value > -1 ? savedPageSize : scope.pageSize.options[0];

                    scope.pagination = {};
                    var savedPageNumber = GridConfiguration.getPageNumber(scope.reportId);
                    scope.pagination.currentPage = savedPageNumber > -1 ? savedPageNumber : 1;
                    scope.pagination.maxSize = 5;
                    scope.pagination.totalItemsCount = 0;
                    scope.pagination.loadedItemsCount = 0;

                    var noneRestorePending = GridConfiguration.isFilterStateEmpty(scope.reportId);
                    scope.initializeData = function() {
                        var initialSorting = {};
                        initialSorting[scope.sorting.field] = scope.sorting.direction;
                        scope.tableParams = new ngTableParams(
                            {
                                page: scope.pagination.currentPage,
                                sorting: initialSorting
                            },
                            {
                                total: 0, // length of data
                                getData: function($defer, params) {

                                    GridCommonService.getData($defer,params,'',
                                        {
                                            entityId: scope.gridConfiguration.url,
                                            query: scope.prepareQueryData(),
                                            page: scope.pagination.currentPage,
                                            pagesize: scope.pageSize.selection.value
                                        },
                                        scope.dateFormat, scope.gridConfiguration.columns,
                                        scope.handleNewDataLoaded, scope.handleErrorData,
                                        noneRestorePending);

                                    noneRestorePending = true;
                                }
                            });
                    };

                    scope.initializeData();
                    scope.enableCheckBoxes();
                };

                scope.enableCheckBoxes = function() {
                    scope.checkboxes = { 'checked': false, items: {} };

                    scope.selectAll = function($event) {
                        var value = $event.target.checked;
                        scope.checkboxes.checked = value;
                        angular.forEach(scope.tableParams.data, function(item) {
                            if (angular.isDefined(item.id)) {
                                scope.checkboxes.items[item.id] = value;
                            }
                        });

                        scope.processCheckBoxesChange();
                    };

                    scope.processCheckBoxesChange = function() {
                        if (!scope.tableParams.data || scope.tableParams.data.length === 0) {
                            return;
                        }

                        var selectedIds =[];

                        var checked = 0, unchecked = 0, nonDeletableChecked = 0,
                            total = scope.tableParams.data.length;

                        angular.forEach(scope.tableParams.data, function(item) {
                            checked   +=  (scope.checkboxes.items[item.id]) || 0;
                            unchecked += (!scope.checkboxes.items[item.id]) || 0;

                            if ((scope.checkboxes.items[item.id])) {
                                selectedIds.push(item.id);
                            }

                            if (scope.checkboxes.items[item.id] && angular.isDefined(item.is_deletable) &&
                                item.is_deletable === false) {
                                nonDeletableChecked++;
                            }
                        });

                        if ((unchecked === 0) || (checked === 0)) {
                            scope.checkboxes.checked = (checked === total);
                        }

                        // grayed checkbox
                        scope.selectAllProp = checked !== 0 && unchecked !== 0;

                        scope.bulkDeleteDisabled = checked === 0 || nonDeletableChecked > 0;

                        scope.$emit('grid.selected.rows.change.event', selectedIds);
                    };
                };
            }
        };
    }]);