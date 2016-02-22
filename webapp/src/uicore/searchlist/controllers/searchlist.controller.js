angular.module('bricata.uicore.searchlist')
    .controller('searchListController', ['$scope', 'filterFilter', 'SearchListDataFormattingService',
    function($scope, filterFilter, SearchListDataFormattingService) {

        $scope.listModel = {};
        $scope.filteredData = [];
        $scope.noDataLoaded = false;
        $scope.noFilteredData = false;
        $scope.isFirstLoadProcessed = false;

        // Clearing Not results found text and returning to initial Signatures data list
        $scope.clearSearchValue = function() {
            $scope.searchedItem.name = '';
            $scope.filterChangeHandler();
        };

        $scope.enableCheckBoxes = function() {
            $scope.selectAllProp = undefined;
            $scope.checkboxes = { 'checked': false, items: {} };

            $scope.selectAll = function($event) {
                var value = $event.target.checked;
                $scope.checkboxes.checked = value;
                $scope.changeAllCheckboxes(value);
            };

            $scope.changeAllCheckboxes = function(value) {
                //this works only for directives without server data call
                angular.forEach($scope.filteredData, function(item) {
                    if (angular.isDefined(item.id)) {
                        $scope.checkboxes.items[item.id] = value;
                    }
                });
                $scope.processCheckBoxesChange();
            };
        };

        $scope.selectionUpdateHandler = function(changedEntityIds, selectionFlag) {
            if (changedEntityIds.length === 0) {
                $scope.checkboxes.items = {};
                $scope.checkboxes.checked = false;
                $scope.selectAllProp = false;
                if (selectionFlag) {
                    $scope.changeAllCheckboxes(true);
                }
            } else {
                var ids = (changedEntityIds+'').split(',');
                angular.forEach(ids, function (id) {
                    $scope.checkboxes.items[id] = selectionFlag;
                });

                $scope.processCheckBoxesChange();
            }
        };

        $scope.processCheckBoxesChange = function() {
            if (!$scope.filteredData || $scope.filteredData.length === 0) {
                return;
            }

            $scope.updateTopCheckbox();

            $scope.selectionChanged()($scope.checkboxes.items);
        };

        $scope.updateTopCheckbox = function() {
            if (!angular.isDefined($scope.filteredData)) {
                return;
            }

            var checked = 0, unchecked = 0,
                total = $scope.filteredData.length;

            angular.forEach($scope.filteredData, function (item) {
                checked += ($scope.checkboxes.items[item.id]) || 0;
                unchecked += (!$scope.checkboxes.items[item.id]) || 0;
            });

            if ((unchecked === 0) || (checked === 0)) {
                $scope.checkboxes.checked = (checked === total && $scope.filteredData.length > 0);
            }

            $scope.selectAllProp = checked !== 0 && unchecked !== 0;
        };

        $scope.setUpUIPagination = function() {
            var skipAutoScroll = false;
            if (angular.isDefined($scope.pagination)) {
                $scope.pagination.totalItemsCount = $scope.filteredData.length;

                var possibleMaxPage = Math.ceil($scope.pagination.totalItemsCount / $scope.pagination.perPage);
                skipAutoScroll = true;
                if (possibleMaxPage < $scope.pagination.currentPage){

                    $scope.pagination.currentPage = Math.max(possibleMaxPage, 1);
                    skipAutoScroll = false;
                }
            } else {
                $scope.pagination = {
                    totalItemsCount: $scope.filteredData.length,
                    currentPage: 1,
                    maxSize: 5,
                    perPage: 100
                };
            }

            $scope.pageChanged(skipAutoScroll);

            if (angular.isDefined($scope.checkboxes)) {
                $scope.updateTopCheckbox();
            }
        };

        $scope.pageChanged = function(skipAutoScroll){
            if (angular.isDefined($scope.serverDataCall())) {
                $scope.isDataLoading = true;
                $scope.serverDataCall()($scope.parentObjectId, $scope.searchedItem.name,
                    $scope.pagination.currentPage).then(
                        function(data) {
                            $scope.pagination.totalItemsCount = data.num_results;
                            $scope.displayedItems = $scope.formatData(data.objects);

                            $scope.isDataLoading = false;

                            if (!$scope.isFirstLoadProcessed) {
                                $scope.isFirstLoadProcessed = true;
                                $scope.noDataLoaded = $scope.pagination.totalItemsCount < 1;
                            }

                            $scope.noFilteredData = !$scope.noDataLoaded &&
                                $scope.displayedItems.length < 1;

                            $scope.$emit('content.changed');
                            $scope.$emit('scrollable.scroll.top');
                });
            } else {
                var startPos = $scope.pagination.perPage * ($scope.pagination.currentPage - 1);
                $scope.displayedItems = $scope.filteredData.slice(startPos, startPos + $scope.pagination.perPage);

                $scope.noDataLoaded = $scope.listModel.entities.length < 1;
                $scope.noFilteredData = $scope.filteredData.length < 1 && $scope.listModel.entities.length > 0;

                $scope.$emit('content.changed');
                if (!skipAutoScroll) {
                    $scope.$emit('scrollable.scroll.top');
                }
            }
        };

        $scope.runPagination = function() {
            if (angular.isDefined($scope.serverDataCall())) {
                $scope.pagination = {
                    currentPage: 1,
                    maxSize: 5,
                    perPage: 100
                };

                $scope.pageChanged();
            } else if ($scope.listModel.entities) {
                $scope.filteredData = $scope.searchedItem.name.length > 0 ?
                    filterFilter($scope.listModel.entities, $scope.searchedItem) : $scope.listModel.entities.slice();
                $scope.setUpUIPagination();
            }
        };

        $scope.filterChangeHandler = function() {
            if (angular.isDefined($scope.serverDataCall())) {
                $scope.pagination.currentPage = 1;
                $scope.pageChanged();
            } else if ($scope.listModel.entities) {
                $scope.filteredData = filterFilter($scope.listModel.entities, $scope.searchedItem);
                $scope.setUpUIPagination();
            }
        };

        $scope.formatData = function(data){
            if (angular.isDefined($scope.columns)) {
                SearchListDataFormattingService.formatData($scope.columns, data);
            }

            return data;
        };

    }]);
