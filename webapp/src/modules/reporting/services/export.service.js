angular.module('bricata.ui.reporting')
    .service('DataExportService', [ 'CommonModalService',
        function(CommonModalService){
            this.showExportDialog = function(labelsObj, selectedEntitiesCount, exportMethod) {
                var modalConfiguration = {
                    templateUrl: 'modules/reporting/views/export.dialog.view.html',
                    controller: 'ExportDialogController',
                    size: 'sm',
                    resolve: {
                        labels: function(){
                            return labelsObj;
                        },
                        selectedCount: function(){
                            return selectedEntitiesCount;
                        },
                        exportHandler: function(){
                            return exportMethod;
                        }
                    }
                };

                CommonModalService.show(modalConfiguration);
            };

        }]);
