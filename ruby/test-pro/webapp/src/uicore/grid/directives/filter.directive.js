angular.module("bricata.uicore.grid")
    .directive("commonFilter", ["$i18next", "$timeout", "moment", "FilterValueItem", "GridConfiguration",
        function($i18next, $timeout, moment, FilterValueItem, GridConfiguration) {
            var filterNames = [
                {name: 'searchFilterVal', default: null},
                {name: 'optionFilterVal', default: 'optionFilterValues'},
                {name: 'valueFilterVal', default: 'valueFilterValues'},
                {name: 'dateStart', default: null},
                {name: 'dateEnd', default: null}
            ];

            return {
                restrict : 'EA',
                templateUrl : 'uicore/grid/views/common-filter.html',
                scope: {
                    reportId: "=",
                    filterConfig: "=",
                    filterChanged: "&",
                    datePickerShowWeeks: "="
                },
                link: function(scope) {
                    scope.filterConfigExists = false;

                    scope.selectedFilters = {};

                    scope.clearFilterState = 'disabled';

                    scope.states = {
                        isSearchFilterInited: false,
                        isValueFilterInited: false,
                        isOptionFilterReady: false,
                        isDateFilterInited: false,
                        showClearFilterBtn: false
                    };

                    var unbindFilterConfigWatcher = scope.$watch('filterConfig', function(value) {
                        if (value && value.valueFilter) {
                            scope.states.showClearFilterBtn = true;
                            scope.loadFilterValueDataAndContinueInit();
                        } else {
                            scope.initializeOtherFilters();
                        }

                        unbindFilterConfigWatcher();
                    });

                    scope.initializeOtherFilters = function() {
                        if (!scope.filterConfig) {
                            return;
                        }

                        scope.filterConfigExists = true;

                        if (scope.filterConfig.searchFilter) {
                            scope.initializeSearchFilter();
                        }

                        if (scope.filterConfig.optionFilter) {
                            scope.states.showClearFilterBtn = true;
                            scope.initializeOptionFilter();
                        }

                        if (scope.filterConfig.dateFilter) {
                            scope.states.showClearFilterBtn = true;
                            scope.datePickerOptions = {
                                startingDay: $i18next('formats.startingDay'),
                                showWeeks: scope.datePickerShowWeeks
                            };
                            scope.initializeDateFilter();
                        }

                        if (!GridConfiguration.isFilterStateEmpty(scope.reportId)) {
                            scope.handleFilterChange();
                        }
                    };

                    scope.loadFilterValueDataAndContinueInit = function() {
                        FilterValueItem.query({entityId: scope.filterConfig.valueFilter.data.url,
                            results_per_page: 1000}).$promise.then(
                            function (receivedData){
                                var allValueItems = receivedData.objects;
                                var valueFilterItems = [];
                                angular.forEach(allValueItems, function(valueItem){
                                    valueFilterItems.push({
                                        value: valueItem[scope.filterConfig.valueFilter.data.valueField],
                                        label: valueItem[scope.filterConfig.valueFilter.data.labelField]
                                    });
                                });

                                scope.initializeValueFilter(valueFilterItems);
                                scope.initializeOtherFilters();
                            }, function() {
                                //alert(error);
                            });
                    };

                    scope.initializeSearchFilter = function() {
                        var savedFilterValue = GridConfiguration.getFilterState(scope.reportId,
                            'searchFilterVal');
                        scope.selectedFilters.searchFilterVal = savedFilterValue ? savedFilterValue : '';

                        scope.$watch('selectedFilters.searchFilterVal', function() {
                            scope.handleFilterChange();
                        });

                        scope.states.isSearchFilterInited = true;
                    };

                    scope.initializeOptionFilter = function() {
                        scope.optionFilterValues = scope.filterConfig.optionFilter.options;

                        var savedFilterValue = GridConfiguration.getFilterState(scope.reportId,
                            'optionFilterVal');
                        if (savedFilterValue) {
                            var optionFilter;
                            for (var i = 0; i < scope.optionFilterValues.length; i++) {
                                optionFilter = scope.optionFilterValues[i];

                                if (optionFilter.value === savedFilterValue.value) {
                                    scope.selectedFilters.optionFilterVal = optionFilter;
                                    break;
                                }
                            }
                        } else {
                            scope.selectedFilters.optionFilterVal = scope.optionFilterValues[0];
                        }

                        scope.states.isOptionFilterReady = true;
                    };

                    scope.initializeValueFilter = function(valueFilterItems) {
                        var defaultFilterValueOption = {
                            value: 'all', label: 'common.everyoneTxt'
                        };

                        valueFilterItems.splice(0, 0, defaultFilterValueOption);

                        scope.valueFilterValues = valueFilterItems;

                        var savedFilterValue = GridConfiguration.getFilterState(scope.reportId,
                            'valueFilterVal');
                        if (savedFilterValue) {
                            angular.forEach(scope.valueFilterValues, function(valueFilter){
                                if (valueFilter.value === savedFilterValue.value) {
                                    scope.selectedFilters.valueFilterVal = valueFilter;
                                    return;
                                }
                            });
                        } else {
                            scope.selectedFilters.valueFilterVal = scope.valueFilterValues[0];
                        }

                        scope.states.isValueFilterInited = true;
                    };

                    scope.initializeDateFilter = function() {
                        scope.selectedFilters.dateStart = null;
                        scope.selectedFilters.dateEnd = null;
                        scope.minDateEnd = null;
                        scope.maxDateStart = null;

                        var savedStartFilter = GridConfiguration.getFilterState(scope.reportId,
                            'dateStart');
                        if (savedStartFilter) {
                            scope.selectedFilters.dateStart =
                                moment(savedStartFilter).format($i18next('formats.gridDateFormat'));
                            scope.minDateEnd = savedStartFilter;
                        }

                        var savedEndFilter = GridConfiguration.getFilterState(scope.reportId, 'dateEnd');
                        if (savedEndFilter) {
                            scope.selectedFilters.dateEnd =
                                moment(savedEndFilter).format($i18next('formats.gridDateFormat'));
                            scope.maxDateStart = savedEndFilter;
                        }

                        scope.startDateChange = function(timeParam) {
                            scope.minDateEnd = timeParam;

                            scope.handleFilterChange();
                        };

                        scope.endDateChange = function(timeParam) {
                            scope.maxDateStart = timeParam;

                            scope.handleFilterChange();
                        };

                        scope.states.isDateFilterInited = true;
                    };

                    scope.checkTimer = null;
                    scope.handleFilterChange = function() {
                        if (scope.checkTimer) {
                            $timeout.cancel(scope.checkTimer);
                        }

                        scope.checkTimer = $timeout(function(){
                            scope.processFilterChange();
                        }, 111, false);
                    };

                    scope.processFilterChange = function() {
                        var isActive = false;
                        var filterData = [];

                        for (var i = 0; i < filterNames.length; i++) {
                            if (scope.selectedFilters[filterNames[i].name] &&
                                (filterNames[i].default === null ||
                                    scope.selectedFilters[filterNames[i].name] !== scope[filterNames[i].default][0])) {

                                GridConfiguration.saveFilterState(scope.reportId, filterNames[i].name,
                                    scope.selectedFilters[filterNames[i].name]);
                                isActive = true;

                                switch (filterNames[i].name) {
                                    case 'searchFilterVal':
                                        var searchFilterData = [];
                                        for (var j = 0; j < scope.filterConfig.searchFilter.fields.length; j++) {
                                            searchFilterData.push({
                                                "name": scope.filterConfig.searchFilter.fields[j],
                                                "op": "like",
                                                "val": '%' + scope.selectedFilters.searchFilterVal + '%'
                                            });
                                        }

                                        filterData.push({"or": searchFilterData});
                                        break;

                                    case 'optionFilterVal':
                                        filterData.push({
                                            "name": scope.filterConfig.optionFilter.field,
                                            "op": "==",
                                            "val": scope.selectedFilters.optionFilterVal.value
                                        });
                                        break;

                                    case 'valueFilterVal':
                                        filterData.push({
                                            "name": scope.filterConfig.valueFilter.field,
                                            "op": "==",
                                            "val": scope.selectedFilters.valueFilterVal.value
                                        });
                                        break;

                                    case 'dateStart':
                                        filterData.push({
                                            "name": scope.filterConfig.dateFilter.field,
                                            "op": "ge",
                                            "val": moment(scope.selectedFilters.dateStart).
                                                startOf('day').format('YYYY-MM-DD')
                                        });
                                        break;

                                    case 'dateEnd':
                                        filterData.push({
                                            "name": scope.filterConfig.dateFilter.field,
                                            "op": "le",
                                            "val": moment(scope.selectedFilters.dateEnd).
                                                startOf('day').add(1, 'days').format('YYYY-MM-DD')
                                        });
                                        break;
                                }
                            } else {
                                GridConfiguration.saveFilterState(scope.reportId, filterNames[i].name, null);
                            }
                        }

                        scope.filterChanged()(filterData);

                        scope.clearFilterState = isActive ? 'active' : 'disabled';
                    };

                    scope.clearFilter = function() {
                        GridConfiguration.clearFilterState(scope.reportId);

                        for (var i = 0; i < filterNames.length; i++) {
                            if (scope.selectedFilters[filterNames[i].name]) {
                                if (filterNames[i].default) {
                                    scope.selectedFilters[filterNames[i].name] = scope[filterNames[i].default][0];
                                } else {
                                    scope.selectedFilters[filterNames[i].name] = undefined;
                                }
                            }
                        }
                        scope.handleFilterChange();
                    };

                    scope.$on('clearFilterEvent', function() {
                        scope.clearFilter();
                    });
                }
            };
        }]);