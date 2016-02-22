angular.module("bricata.ui.signatureclasstypes")
    .directive("signatureClassTypesHeader", ["CommonNavigationService", "DataExportService", "BricataUris",
        function (CommonNavigationService, DataExportService, BricataUris) {

            return {
                restrict: 'E',
                templateUrl: 'modules/signatureclasstypes/views/signatureClassTypesNavigation.html',
                link: function(scope, element) {
                    scope.totalSignatureClassTypesFound = 0;
                    scope.selectedIds = [];

                    scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                        scope.totalSignatureClassTypesFound = totalCount;
                        scope.selectedIds = [];
                    });

                    scope.$on('grid.selected.rows.change.event', function(event, selectedIds) {
                        scope.selectedIds = selectedIds;
                    });

                    scope.openCreateSignatureClassTypeWizard = function() {
                        CommonNavigationService.navigateToSignatureClassTypeWizardPage();
                    };

                    scope.showImportDialog = function() {
                        var eventData = {
                            actionName: "classTypeImport",
                            actionType: "modal",
                            data: []
                        };

                        scope.$broadcast('grid.header.invoke.row.action', eventData);
                    };

                    scope.exportClassTypes = function(){
                        DataExportService.showExportDialog({
                            title: 'signatureClassTypes.exportDialogTitle',
                            all: 'signatureClassTypes.exportAll',
                            selected: 'signatureClassTypes.exportSelected',
                            selectedMsg: 'signatureClassTypes.exportSelectedMsg',
                            selectedCount: 'signatureClassTypes.exportSelectedCount'
                        }, scope.selectedIds.length, scope.requestExportFile);
                    };

                    scope.requestExportFile = function(isAll){
                        var query = {
                            ids: isAll ? [] : scope.selectedIds
                        };
                        element.append("<iframe src='" + BricataUris.signatureClassTypeExport + "?q=" +
                            JSON.stringify(query) + "' style='display: none;'></iframe>");
                    };
                }
            };
        }]);