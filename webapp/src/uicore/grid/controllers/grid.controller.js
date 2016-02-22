angular.module('bricata.uicore.grid')
    .controller('GridController',
    ['$scope', 'GridConfiguration',
        function($scope, GridConfiguration) {

            $scope.filterData = [];

            $scope.selectedRow = null;

            $scope.states = {
                isGridTopLevelMsg: false,
                isNoFilteredData: false,
                dataLoadErrorOccured: false,
                isRowSelectionEnabled: true
            };

            $scope.prepareQueryData = function() {
                var query = {};
                query.order_by = [$scope.sorting];

                if ($scope.filterData.length > 0) {
                    query.filters = $scope.filterData;
                }

                return JSON.stringify(query);
            };

            $scope.filterChanged = function(value) {
                var isReloadNeeded = value.length > 0 || $scope.filterData.length !== value.length;
                $scope.filterData = value;
                if (isReloadNeeded) {
                    $scope.pagination.currentPage = 1;
                    GridConfiguration.savePageNumber($scope.reportId, 1);
                    $scope.reloadGridData();
                }
            };

            $scope.reloadDataAfterError = function() {
                $scope.resetGridOptions();
                $scope.sortTable($scope.gridConfiguration.defaultSorting.field);
                $scope.reloadGridData();
                $scope.states.dataLoadErrorOccured = false;
            };

            $scope.resetGridOptions = function() {
                GridConfiguration.clearState($scope.reportId);
                $scope.filterData = [];
                $scope.pageSize.selection = $scope.pageSize.options[0];
                $scope.pagination.currentPage = 1;
                $scope.$broadcast('clearFilterEvent');
            };

            $scope.handleNewDataLoaded = function(totalAvailable, totalLoaded, currentPageNumber, receivedData) {
                $scope.updateTopLevelTotal(totalAvailable);

                $scope.pagination.loadedItemsCount = totalLoaded;
                $scope.pagination.currentPage = currentPageNumber;
                GridConfiguration.savePageNumber($scope.reportId, currentPageNumber);

                $scope.checkFilterReturnedData();

                $scope.markChangedRow(receivedData);
            };

            $scope.updateTopLevelTotal = function(topLevelTotal) {
                $scope.pagination.totalItemsCount = topLevelTotal;
                $scope.$emit('grid.total.rows.change.event', $scope.pagination.totalItemsCount);
            };

            $scope.handleErrorData = function(reason) {
                GridConfiguration.handleDataLoadError(reason,
                    $scope.gridConfiguration.labels.loadFailed, $scope.processDataError);
            };

            $scope.processDataError = function() {
                $scope.updateTopLevelTotal(0);
                $scope.states.dataLoadErrorOccured = true;
            };

            $scope.clearFilter = function() {
                $scope.$broadcast('clearFilterEvent');
                $scope.states.isNoFilteredData = false;
            };

            $scope.sortTable = function(columnField, sortDirection) {
                $scope.clearRowStatus();
                $scope.clearCheckBoxSelections();

                if (!sortDirection) {
                    sortDirection = $scope.tableParams.isSortBy(columnField, 'asc') ? 'desc' : 'asc';
                }
                $scope.tableParams.sorting(columnField,
                    sortDirection);

                $scope.sorting.field = columnField;
                $scope.sorting.direction = sortDirection;

                GridConfiguration.saveSorting($scope.reportId, columnField, sortDirection);
            };

            $scope.reloadGridData = function() {
                $scope.clearRowStatus();
                $scope.clearCheckBoxSelections();
                $scope.tableParams.reload();
            };

            $scope.pageChanged = function() {
                GridConfiguration.savePageNumber($scope.reportId, $scope.pagination.currentPage);
                $scope.reloadGridData();
            };

            $scope.changePageSize = function(selectedPageSize) {
                $scope.pageSize.selection = selectedPageSize;

                $scope.pagination.currentPage = 1;
                GridConfiguration.savePageNumber($scope.reportId, 1);
                GridConfiguration.savePageSize($scope.reportId, $scope.pageSize.selection);
                $scope.reloadGridData();
            };

            $scope.rowAction = function(action, type, entityObjects, $event) {
                if (type === 'rowdetail') {
                    $event.stopImmediatePropagation();
                    $scope.handleRowClick(entityObjects[0], type);
                } else {
                    var actionObject = {
                        actionName: action,
                        actionType: type,
                        data: entityObjects
                    };

                    $scope.rowActionHandler()(actionObject);
                }
            };

            $scope.$on('grid.disable.row.selection', function() {
                $scope.states.isRowSelectionEnabled = false;
            });

            $scope.$on('grid.enable.row.selection', function() {
                $scope.states.isRowSelectionEnabled = true;
            });

            $scope.handleRowClick = function(entityObject, columnClick) {
                if (!angular.isDefined($scope.gridConfiguration.rowDetailsView) ||
                    !angular.isDefined($scope.gridConfiguration.rowDetailsView.src)) {
                    return;
                }

                if (!$scope.states.isRowSelectionEnabled) {
                    return;
                }

                if (columnClick === 'check') {
                    return;
                }

                if (columnClick === 'action') {
                    $scope.selectedRow = null;
                    angular.forEach($scope.tableParams.data, function(item) {
                        item.$selected = false;
                    });
                    return;
                }

                $scope.clearRowStatus();

                var item;
                for (var i = 0; i < $scope.tableParams.data.length; i++) {
                    item = $scope.tableParams.data[i];

                    if (entityObject.id === item.id) {
                        if (item.$selected) {
                            item.$selected = false;
                            break;
                        }
                        item.$selected = true;
                        $scope.selectedRow = entityObject;
                    } else {
                        item.$selected = false;
                    }
                }
            };

            $scope.clearRowStatus = function() {
                if ($scope.tableParams && $scope.tableParams.data) {
                    angular.forEach($scope.tableParams.data, function(item) {
                        item.isChanged = false;
                    });
                }

                $scope.states.isGridTopLevelMsg = false;
            };

            $scope.handleDeleteStatus = function() {
                $scope.reloadGridData();
            };

            $scope.handleEditStatus = function() {
                $scope.reloadGridData();
            };

            $scope.handleCreateStatus = function() {
                $scope.resetGridOptions();
                $scope.sortTable($scope.gridConfiguration.createdSorting.field,
                    $scope.gridConfiguration.createdSorting.direction);
                $scope.reloadGridData();
            };

            $scope.checkFilterReturnedData = function() {
                $scope.states.isNoFilteredData =
                    $scope.pagination.totalItemsCount === 0 && $scope.filterData.length > 0;
            };

            $scope.bulkDeleteHandler = function() {
                var entityObjects =[];
                angular.forEach($scope.tableParams.data, function(item) {
                    if ($scope.checkboxes.items[item.id]) {
                        entityObjects.push(item);
                    }
                });
                $scope.rowAction('bulkDelete', 'modal', entityObjects);
            };

            $scope.clearCheckBoxSelections = function() {
                $scope.checkboxes = { 'checked': false, items: {} };
                $scope.selectAllProp = false;
                $scope.bulkDeleteDisabled = true;
            };

            $scope.markChangedRow = function(rawData) {
                if ($scope.changedObject && $scope.changedObject.data) {

                    if ($scope.changedObject.data.requiresReload) {
                        $scope.reloadGridData();
                    }

                    $scope.rowChangedObject = angular.copy($scope.changedObject);

                    var items = rawData ? rawData : $scope.tableParams.data;
                    if ($scope.changedObject.data.id) {
                        $scope.states.isGridTopLevelMsg = false;

                        var isItemMarked = false;
                        angular.forEach(items, function(item) {
                            if (item.id === $scope.changedObject.data.id) {
                                item.isChanged = true;
                                isItemMarked = true;

                                if ($scope.changedObject.data.field && $scope.changedObject.data.value) {
                                    item[$scope.changedObject.data.field] = $scope.changedObject.data.value;
                                }
                            } else {
                                item.isChanged = false;
                            }
                        });

                        if (!isItemMarked) {
                            $scope.states.isGridTopLevelMsg = true;
                        }
                    } else {
                        $scope.states.isGridTopLevelMsg = true;
                    }

                    if ($scope.changedObject.data.bulkChangeIds) {
                        angular.forEach(items, function(item) {
                            angular.forEach($scope.changedObject.data.bulkChangeIds, function(id) {
                                if (item.id === id && $scope.changedObject.data.field &&
                                    $scope.changedObject.data.value) {
                                    item[$scope.changedObject.data.field] = $scope.changedObject.data.value;
                                }
                            });
                        });
                    }

                    $scope.changedObject = null;
                }
            };

        }]);
