angular.module("bricata.ui.policy")
    .directive("policyGridRowDetails", ['PolicyDataService',
        function(PolicyDataService) {
            return {
                restrict : 'E',
                templateUrl : 'modules/policy/views/rowinfo/details/policy-grid-row-details-content.html',
                link: function(scope) {
                    scope.policyDetailsLoaded = false;
                    scope.policySignaturesLoadMethod = PolicyDataService.getSignaturesPaginated;
                    scope.policySensorsLoadMethod = PolicyDataService.getSensors;

                    scope.sensorColumns = [
                        {'field' : 'sensor', 'type': 'text',
                            'style': {'min-width': '120px', 'max-width': '120px'}},
                        {'field' : 'interface', 'type': 'text',
                            'style': {'min-width': '50px', 'max-width': '50px'}},
                        {'field' : 'action', 'type': 'text',
                            'style': {'min-width': '50px', 'max-width': '50px'}},
                        {'field' : 'last_applied_by', 'type': 'text',
                            'style': {'min-width': '100px', 'max-width': '100px'}},
                        {'field' : 'last_applied_at', 'type': 'time',
                            'style': {'min-width': '140px', 'max-width': '140px'}}
                    ];

                    scope.collapseDetails = function() {
                        scope.selectedRow.$selected = false;
                    };

                    scope.policyDetailsLoaded = true;
                }
            };
        }]);