angular.module("bricata.ui.signature")
    .directive('signatureInformation',['ConfigurationService',
        function(ConfigurationService) {
        return {
            restrict: 'E',
            templateUrl: 'modules/signature/views/newsignature/signature-information.html',
            link: function(scope) {
                scope.controlKeywords = ConfigurationService.getFlowControlKeywords();
                scope.contentKeywords = ConfigurationService.getContentKeywords();
            }
        };
    }]);