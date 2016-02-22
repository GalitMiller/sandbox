angular.module("bricata.ui.referencetype")
    .directive("referenceTypeHeaderNavigation", [ "CommonNavigationService", "DataExportService", "BricataUris",
        function (CommonNavigationService, DataExportService, BricataUris) {

            return {
                restrict: 'E',
                templateUrl: 'modules/referencetype/views/references-header.html',
                link: function(scope, element) {
                    scope.totalReferenceTypesFound = 0;
                    scope.selectedIds = [];

                    scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                        scope.totalReferenceTypesFound = totalCount;
                        scope.selectedIds = [];
                    });

                    scope.$on('grid.selected.rows.change.event', function(event, selectedIds) {
                        scope.selectedIds = selectedIds;
                    });

                    scope.navToWizardPage = function() {
                        CommonNavigationService.navigateToReferenceTypeWizardPage();
                    };

                    scope.showImportDialog = function() {
                        var eventData = {
                            actionName: "referenceImport",
                            actionType: "modal",
                            data: []
                        };

                        scope.$broadcast('grid.header.invoke.row.action', eventData);
                    };

                    scope.exportReferences = function(){
                        DataExportService.showExportDialog({
                            title: 'referenceTypesGrid.exportDialogTitle',
                            all: 'referenceTypesGrid.exportAll',
                            selected: 'referenceTypesGrid.exportSelected',
                            selectedMsg: 'referenceTypesGrid.exportSelectedMsg',
                            selectedCount: 'referenceTypesGrid.exportSelectedCount'
                        }, scope.selectedIds.length, scope.requestExportFile);
                    };

                    scope.requestExportFile = function(isAll){
                        var query = {
                            ids: isAll ? [] : scope.selectedIds
                        };
                        element.append("<iframe src='" + BricataUris.referenceExport + "?q=" + JSON.stringify(query) +
                            "' style='display: none;'></iframe>");
                    };
                }
            };
        }]);