angular.module("bricata.uicore.searchlist")
    .directive("searchListColumnar", [
        function () {
            return {
                restrict: 'E',
                controller: 'searchListController',
                templateUrl: 'uicore/searchlist/views/searchListColumnar.html',
                scope: {
                    sectionTitle: '@',
                    searchPlaceholder: '@',
                    data: '=',
                    columns: '=',
                    absentDataMsg: '@',
                    parentObjectId: '@',
                    serverDataCall: '&'
                },
                link: function(scope) {
                    scope.isDataLoading = false;

                    scope.searchedItem = {
                        name: ''
                    };

                    scope.$watch('data.length', function() {
                        if (!angular.isDefined(scope.serverDataCall())) {
                            scope.listModel.entities = scope.data;
                        }

                        scope.runPagination();
                    });

                    scope.$watch('searchedItem.name', function(value) {
                        if (value && value.length > 0 &&
                            scope.listModel && scope.listModel.entities &&
                            scope.listModel.entities.length > scope.displayedQuantity) {
                            scope.displayedQuantity = scope.listModel.entities.length;
                        }

                        scope.$emit('content.changed');
                    });
                }
            };
        }]);