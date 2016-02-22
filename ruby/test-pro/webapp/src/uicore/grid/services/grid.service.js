angular.module("bricata.uicore.grid")
    .factory("GridCommonService",
    ["GridConfiguration", "CommonGridItem", "moment", "gridCustomColumns",
        function(GridConfiguration, CommonGridItem, moment, gridCustomColumns){

            var EMPTY_CELL_VALUE = '-';
            var fullData = {};
            var allGridItems = [];

            var getRange = function(type, data){

                var level = "null",
                    value = parseInt(data) ? data : undefined;

                var ranges = GridConfiguration.detectRangeByType(type);

                for (var i = 0; i < ranges.length; i++) {
                    if (ranges[i].minValue <= value && value <= ranges[i].maxValue){
                        level = ranges[i].levelName;
                        break;
                    }
                }

                return level;
            };

            var formatStandardColumnValue = function(column, item) {
                if (!isValueSet(item[column.field])) {
                    item[column.field] = EMPTY_CELL_VALUE;
                }

                if (column.subfield && !isValueSet(item[column.field][column.subfield])) {
                    item[column.field] = {};
                    item[column.field][column.subfield] = EMPTY_CELL_VALUE;
                }
            };

            var setItemValue = function(column, item, value) {
                if (column.subfield) {
                    if (!isValueSet(item[column.field])) {
                        item[column.field] = {};
                    }
                    item[column.field][column.subfield] = value;
                } else {
                    item[column.field] = value;
                }
            };

            var getItemValue = function(column, item) {
                if (column.subfield) {
                    return isValueSet(item[column.field]) && isValueSet(item[column.field][column.subfield]) ?
                        item[column.field][column.subfield] : EMPTY_CELL_VALUE;
                } else {
                    return isValueSet(item[column.field]) ? item[column.field] : EMPTY_CELL_VALUE;
                }
            };

            var isValueSet = function(object){
                return angular.isDefined(object) && object !== null;
            };

            var formatCustomColumnValue = function(column, item, dateFormat) {
                var valueToSet = EMPTY_CELL_VALUE;
                var classToSet = '';

                if (isValueSet(item[column.field])) {
                    var i;
                    switch(column.type) {
                        case gridCustomColumns.date:
                            valueToSet = moment(getItemValue(column, item)).format(dateFormat);
                            break;
                        case gridCustomColumns.range:
                            setItemValue(column, item, getRange(column.field, getItemValue(column, item)));
                        /* falls through */
                        case gridCustomColumns.label:
                            for (i = 0; i < column.values.length; i++) {
                                if (column.values[i].match === getItemValue(column, item)) {
                                    valueToSet = column.values[i].value;
                                    classToSet = column.values[i].class;
                                    break;
                                }
                            }
                            break;
                        case gridCustomColumns.dynamic:
                            valueToSet = getItemValue(column, item);
                            break;
                        /* 'value' and 'dynamicValue' */
                        default:
                            for (i = 0; i < column.values.length; i++) {
                                if (column.values[i].match === getItemValue(column, item)) {
                                    valueToSet = column.values[i].value;
                                    break;
                                }
                            }
                            break;
                    }
                }

                setItemValue(column, item,
                    (classToSet) ? {value : valueToSet, class: classToSet} : valueToSet);
            };


            var formatData = function(columnDefinitions, dateFormat) {
                var i;
                var column;
                angular.forEach(allGridItems, function(item){
                    for (i = 0; i < columnDefinitions.length; i++) {
                        column = columnDefinitions[i];

                        if (gridCustomColumns[column.type]) {
                            if (column.type === gridCustomColumns.severity) {
                                var severityObj = angular.isDefined(item.severity) ? item.severity : item;

                                setItemValue(column, item, {
                                    value : severityObj.name,
                                    class: {'color': severityObj.text_color, 'background-color': severityObj.bg_color}
                                });
                            } else {
                                formatCustomColumnValue(column, item, dateFormat);
                            }
                        } else {
                            formatStandardColumnValue(column, item);
                        }
                    }
                });
            };

            var service = {
                getData:function($defer, params, filter, requestParams, dateFormat, columnDefinitions,
                                 successHandler, errorHandler, noRestoreStatePending){

                    if (noRestoreStatePending) {
                        CommonGridItem.query(requestParams).$promise.then(function (receivedData){
                            fullData = receivedData;
                            allGridItems = fullData.objects;
                            formatData(columnDefinitions, dateFormat);

                            params.total(allGridItems.length);

                            $defer.resolve(allGridItems);

                            successHandler(fullData.num_results, allGridItems.length, fullData.page, allGridItems);
                        }, function(reason) {
                            errorHandler(reason);
                        });
                    }
                }
            };
            return service;
        }]);