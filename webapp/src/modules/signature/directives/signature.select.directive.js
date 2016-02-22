angular.module("bricata.ui.signature")
    .directive("signatureSelect", [
        function () {
            return {
                restrict: 'E',
                templateUrl: 'modules/signature/views/signature-select.html',
                controller: 'SignatureSelectController',
                scope: {
                    preselectionModel: "=",
                    selectionModel: "=",
                    selectionMode: "="
                },
                link: function(scope) {
                    scope.$watch('selectionMode', function() {
                        scope.changeSelectionMode();
                    });
                }
            };
        }]);