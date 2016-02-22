angular.module("bricata.ui.signature")
    .directive("signaturesHeader",
    ["CommonNavigationService", "BricataUris", "CommonErrorMessageService", "DataExportService",
    function (CommonNavigationService, BricataUris, CommonErrorMessageService, DataExportService) {

        return {
            restrict: 'E',
            templateUrl: 'modules/signature/views/signaturesNavigation.html',
            link: function(scope, element) {
                scope.totalSignaturesFound = 0;
                scope.selectedIds = [];

                scope.$on('grid.total.rows.change.event', function(event, totalCount) {
                    scope.totalSignaturesFound = totalCount;
                    scope.selectedIds = [];
                });

                scope.$on('grid.selected.rows.change.event', function(event, selectedIds) {
                    scope.selectedIds = selectedIds;
                });

                scope.openSignatureWizard = function() {
                    CommonNavigationService.navigateToSignatureWizardPage();
                };

                scope.openImportSignatureDialog = function() {
                    var eventData = {
                        actionName: "signatureImport",
                        actionType: "modal",
                        data: []
                    };

                    scope.$broadcast('grid.header.invoke.row.action', eventData);
                };

                scope.exportSignatures = function(){
                    DataExportService.showExportDialog({
                        title: 'severitiesGrid.exportDialogTitle',
                        all: 'severitiesGrid.exportAll',
                        selected: 'severitiesGrid.exportSelected',
                        selectedMsg: 'severitiesGrid.exportSelectedMsg',
                        selectedCount: 'severitiesGrid.exportSelectedCount'
                    }, scope.selectedIds.length, scope.requestExportFile);
                };

                scope.requestExportFile = function(isAll){
                    var query = {
                        ids: isAll ? [] : scope.selectedIds
                    };
                    element.append("<iframe src='" + BricataUris.signatureExport + "?q=" + JSON.stringify(query) +
                        "' style='display: none;'></iframe>");
                };
            }
        };
    }]);