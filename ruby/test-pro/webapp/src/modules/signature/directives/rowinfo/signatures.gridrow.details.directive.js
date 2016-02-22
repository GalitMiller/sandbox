angular.module("bricata.ui.signature")
    .directive("signaturesGridRowDetails",
    ['$cookies', '$q', 'SignatureDataService', 'CommonErrorMessageService', 'BricataUris',
        function($cookies, $q, SignaturesDataService, CommonErrorMessageService, BricataUris) {
            return {
                restrict : 'E',
                templateUrl : 'modules/signature/views/rowinfo/details/signatures-grid-row-details-content.html',
                link: function(scope) {
                    scope.signaturesDetailsLoaded = false;
                    scope.signaturesDetailsLoadError = false;
                    scope.noEventsFound = false;

                    scope.loadSignatureDetails = function() {
                        $q.all([
                            SignaturesDataService.getSignatureRules(scope.selectedRow.id),
                            SignaturesDataService.getSignatureMappings(scope.selectedRow.sid)
                        ]).then(function(data) {
                            scope.signatureDetails = data[0];
                            var mappings = data[1].reverse();
                            var queryObj = {};
                            scope.noEventsFound = mappings.length < 1;
                            for (var i = 0; i < mappings.length; i++) {
                                queryObj[i] = {
                                    column: 'signature',
                                    operator: 'is',
                                    value: mappings[i],
                                    enabled: true
                                };
                            }

                            scope.searchModel = {
                                signatureSearchResultURL: BricataUris.signatureSearchedItems,
                                matchAll: true,
                                query: JSON.stringify(queryObj),
                                token: $cookies.csrf
                            };

                            scope.signaturesDetailsLoaded = true;

                            scope.$broadcast('content.changed');

                        }, function error(reason) {
                            scope.handleError(reason);
                        });
                    };

                    scope.collapseDetails = function() {
                        scope.selectedRow.$selected = false;
                    };

                    scope.handleError = function(reason) {
                        if (!scope.signaturesDetailsLoadError) {
                            scope.signaturesDetailsLoadError = true;
                            CommonErrorMessageService.showErrorMessage("errors.signatureDetailsDataError", reason, null,
                                scope.processError);
                        }
                    };

                    scope.processError = function() {
                        scope.signaturesDetailsLoaded = true;
                    };

                    scope.reloadSignaturesDetails = function() {
                        scope.signaturesDetailsLoaded = false;
                        scope.signaturesDetailsLoadError = false;

                        scope.loadSignatureDetails();
                    };

                    scope.loadSignatureDetails();
                }
            };
        }]);