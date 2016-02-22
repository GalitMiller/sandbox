angular.module('bricata.uicore.searchlist')
    .factory('SearchListDataFormattingService', ['$i18next', 'moment',
        function($i18next, moment){

            var service = {
                formatData:function(columns, data){

                    angular.forEach(columns, function(column){
                        if (column.type === 'time'){
                            var dateTimeFormat = $i18next('formats.dateWithTimeFormat');

                            angular.forEach(data, function(item){
                                item[column.field] = moment(item[column.field]).format(dateTimeFormat);
                            });
                        }
                    });
                }
            };
            return service;
        }]);