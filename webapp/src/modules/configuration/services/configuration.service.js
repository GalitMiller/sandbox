angular.module("bricata.ui.configuration")
    .factory("ConfigurationService", ["$q", "ConfigurationItem",
        function($q, ConfigurationItem){
            var appConfig = {};
            var service = {
                loadConfiguration: function(){
                    var randomParam = Math.floor(Math.random() * 100000000000000);
                    var deferred = $q.defer();
                    ConfigurationItem.query({_: randomParam}).$promise.then(function (config){
                        deferred.resolve(config);
                    }, function() {
                        deferred.reject();
                    });

                    return deferred.promise;
                },

                setConfiguration: function(configData) {
                    appConfig = configData;
                },

                getGridPageSizes: function(){
                    return (angular.isDefined(appConfig.grid.pageSizes)) ? appConfig.grid.pageSizes : [20, 30, 50];
                },

                getPolicyTypes: function(){
                    return angular.isDefined(appConfig.policyTypes) ? appConfig.policyTypes : [];
                },

                getPolicyDeploymentModes: function() {
                    return angular.isDefined(appConfig.policyDeploymentModes) ? appConfig.policyDeploymentModes : [];
                },

                getPolicyActions: function() {
                    return angular.isDefined(appConfig.policyActions) ? appConfig.policyActions : [];
                },

                getSignatureActions: function() {
                    return angular.isDefined(appConfig.signatureActions) ? appConfig.signatureActions : [];
                },

                getSignatureHelpLinks: function() {
                    return angular.isDefined(appConfig.signatureHelpLinks) ? appConfig.signatureHelpLinks : [];
                },

                getFlowControlKeywords: function() {
                    return angular.isDefined(appConfig.flowControlKeywords) ? appConfig.flowControlKeywords : [];
                },

                getContentKeywords: function() {
                    return angular.isDefined(appConfig.contentKeywords) ? appConfig.contentKeywords : [];
                },

                getSeverityRanges: function() {
                    return angular.isDefined(
                        appConfig.signatureSeverityRanges) ? appConfig.signatureSeverityRanges : [];
                }
            };
            return service;
        }]);