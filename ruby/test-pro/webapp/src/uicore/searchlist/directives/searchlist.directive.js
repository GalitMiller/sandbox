angular.module("bricata.uicore.searchlist")
    .directive("searchList", ["$templateCache", "$compile",
    function ($templateCache, $compile) {
        return {
            restrict: 'E',
            controller: 'searchListController',
            scope: {
                sectionTitle: '@',
                signatureIcon: '@',
                searchPlaceholder: '@',
                data: '=',
                selectionChanged: '&',
                clearAllSelected: '=',
                removeSelection: '=',
                absentDataMsg: '@',
                topLvlSelectionUpdater: '=',
                showRemoveButton: '=',
                parentObjectId: '@',
                serverDataCall: '&'
            },
            link: function(scope, element) {
                var preselectedIdsData = null;
                scope.isDataLoading = false;

                scope.searchedItem = {
                    name: ''
                };

                scope.$watch('data.length', function() {
                    if (!angular.isDefined(scope.serverDataCall())) {
                        scope.listModel.entities = scope.data;
                    }

                    scope.runPagination();

                    if (scope.listModel.entities && scope.listModel.entities.length > 0 && preselectedIdsData) {
                        scope.selectionUpdateHandler(preselectedIdsData, true);
                        preselectedIdsData = null;
                    }

                    if (angular.isDefined(scope.checkboxes)) {
                        scope.updateTopCheckbox();
                    }
                });

                scope.$watch('searchedItem.name', function(value) {
                    if (value && value.length > 0 &&
                        scope.listModel && scope.listModel.entities &&
                        scope.listModel.entities.length > scope.displayedQuantity) {
                        scope.displayedQuantity = scope.listModel.entities.length;
                    }

                    scope.$emit('content.changed');
                });

                if (angular.isDefined(scope.signatureIcon) && scope.signatureIcon === 'checkbox') {
                    scope.enableCheckBoxes();
                }

                if (angular.isDefined(scope.topLvlSelectionUpdater)) {
                    scope.topLvlSelectionUpdater.updateSelection = function(ids, isSelected, isPreselectionMode) {
                        if ((!scope.listModel.entities || scope.listModel.entities.length === 0) &&
                            isPreselectionMode) {

                            preselectedIdsData = ids;
                        } else {
                            scope.selectionUpdateHandler(ids, isSelected);
                        }
                    };
                }

                switch (scope.signatureIcon) {
                    case 'checkbox':
                        element.html($templateCache.get('uicore/searchlist/views/searchListCheckbox.html'));
                        break;
                    case 'remove':
                        element.html($templateCache.get('uicore/searchlist/views/searchListRemove.html'));
                        break;
                    default:
                        element.html($templateCache.get('uicore/searchlist/views/searchList.html'));
                        break;
                }

                $compile(element.contents())(scope);
            }
        };
    }]);