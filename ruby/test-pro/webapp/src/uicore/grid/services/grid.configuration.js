angular.module("bricata.uicore.grid")
    .provider("GridConfiguration", function(){

        this.getConfigProvider = undefined;
        this.getReportIdMethod = undefined;
        this.dataLoadErrorHandler = undefined;
        this.gridPageSizes = undefined;
        this.rangeDetectMethod = undefined;
        this.gridRequestUrl = undefined;
        this.filterRequestUrl = undefined;

        this.setConfigProvider = function(newConfigProvider) {
            this.getConfigProvider = newConfigProvider;
        };

        this.setReportIdMethod = function(newReportIdMethod) {
            this.getReportIdMethod = newReportIdMethod;
        };

        this.setDataLoadErrorHandler = function(newDataLoadErrorHandler) {
            this.dataLoadErrorHandler = newDataLoadErrorHandler;
        };

        this.setGridPageSizes = function(newGridPageSizes) {
            this.gridPageSizes = newGridPageSizes;
        };

        this.setRangeDetectMethod = function(newRangeDetectMethod) {
            this.rangeDetectMethod = newRangeDetectMethod;
        };

        this.setGridRequestUrl = function(newGridRequestUrl) {
            this.gridRequestUrl = newGridRequestUrl;
        };

        this.setFilterRequestUrl = function(newFilterRequestUrl) {
            this.filterRequestUrl = newFilterRequestUrl;
        };

        this.$get = [
            function() {

                var gridStatePrototype = {
                    pageNumber: -1,
                    itemsPerPage: -1,
                    selectedFilters: {},
                    sorting: null
                };

                var gridStates = {};

                var getGridState = function(reportId) {
                    if (!angular.isDefined(gridStates[reportId])) {
                        gridStates[reportId] = angular.copy(gridStatePrototype);
                    }

                    return gridStates[reportId];
                };

                var getConfigProvider = this.getConfigProvider;
                var getReportIdMethod = this.getReportIdMethod;
                var dataLoadErrorHandler = this.dataLoadErrorHandler;
                var gridPageSizes = this.gridPageSizes;
                var rangeDetectMethod = this.rangeDetectMethod;
                var gridRequestUrl = this.gridRequestUrl;
                var filterRequestUrl = this.filterRequestUrl;

                // ROOT URL should be on the bottom
                return {
                    getGridRequestUrl: function() {
                        return gridRequestUrl;
                    },

                    getFilterRequestUrl: function() {
                        return filterRequestUrl;
                    },

                    getGridPageSizes: function() {
                        return gridPageSizes();
                    },

                    detectRangeByType: function(type) {
                        return rangeDetectMethod(type);
                    },

                    getReportId: function() {
                        return getReportIdMethod();
                    },

                    getConfiguration:function(reportId){
                        return getConfigProvider(reportId).getGridConfiguration();
                    },

                    getModal:function(reportId, actionName) {
                        return getConfigProvider(reportId).getActionModal(actionName);
                    },

                    redirectToPage:function(reportId, actionName) {
                        return getConfigProvider(reportId).performRedirect(actionName);
                    },

                    handleDataLoadError: function(reason, errMsg, errProcessor) {
                        dataLoadErrorHandler(reason, errMsg, errProcessor);
                    },

                    saveFilterState: function(reportId, key, value){
                        var gridState = getGridState(reportId);
                        gridState.selectedFilters[key] = value;
                    },
                    getFilterState: function(reportId, key){
                        var gridState = getGridState(reportId);
                        return gridState.selectedFilters[key];
                    },
                    clearFilterState: function(reportId){
                        var gridState = getGridState(reportId);
                        gridState.selectedFilters = {};
                    },
                    isFilterStateEmpty: function(reportId){
                        var gridState = getGridState(reportId);
                        var result = true;
                        for (var key in gridState.selectedFilters) {
                            if (gridState.selectedFilters[key]) {
                                result = false;
                                break;
                            }
                        }

                        return result;
                    },
                    savePageNumber: function(reportId, pageNum){
                        var gridState = getGridState(reportId);
                        gridState.pageNumber = pageNum;
                    },
                    getPageNumber: function(reportId){
                        var gridState = getGridState(reportId);
                        return gridState.pageNumber;
                    },
                    savePageSize: function(reportId, pageSize){
                        var gridState = getGridState(reportId);
                        gridState.itemsPerPage = pageSize;
                    },
                    getPageSize: function(reportId){
                        var gridState = getGridState(reportId);
                        return gridState.itemsPerPage;
                    },
                    saveSorting: function(reportId, sortField, sortDirection) {
                        var gridState = getGridState(reportId);
                        gridState.sorting = {
                            field: sortField,
                            direction: sortDirection
                        };
                    },
                    getSorting: function(reportId){
                        var gridState = getGridState(reportId);
                        return gridState.sorting;
                    },
                    clearState: function(reportId){
                        if (angular.isDefined(gridStates[reportId])) {
                            gridStates[reportId] = angular.copy(gridStatePrototype);
                        }
                    }
                };
            }];
    });