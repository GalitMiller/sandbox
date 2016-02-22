angular.module("bricata.ui.reporting")
    .factory("ReportingService", ['CommonNavigationService', 'BricataUris', 'gridReportIds', 'ConfigurationService',
        'PolicyGridConfigurationService',
        'InactiveSensorsGridConfigurationService', 'SignaturesGridConfigurationService',
        'SignatureCategoriesGridConfigurationService', 'ReferenceTypesGridConfigurationService',
        'SeveritiesGridConfigurationService', 'SignatureClassTypesGridConfigurationService',
        'CommonErrorMessageService',
        function(CommonNavigationService, BricataUris, gridReportIds, ConfigurationService,
                 PolicyGridConfigurationService,
                 InactiveSensorsGridConfigurationService, SignaturesGridConfigurationService,
                 SignatureCategoriesGridConfigurationService, ReferenceTypesGridConfigurationService,
                 SeveritiesGridConfigurationService, SignatureClassTypesGridConfigurationService,
                 CommonErrorMessageService){

            /* order is important here - put longest sub links on top and shorter parent - bottom */
            var CONFIGURATION_SET = [
                {
                    reportId: gridReportIds.policyReportId,
                    configProvider: PolicyGridConfigurationService,
                    url: BricataUris.pages.policiesPage
                },
                {
                    reportId: gridReportIds.inactiveSensorsReportId,
                    configProvider: InactiveSensorsGridConfigurationService,
                    url: BricataUris.pages.inactiveSensorPage
                },
                {
                    reportId: gridReportIds.signatureCategoriesReportId,
                    configProvider: SignatureCategoriesGridConfigurationService,
                    url: BricataUris.pages.signatureCategoriesPage
                },
                {
                    reportId: gridReportIds.signatureClassTypesReportId,
                    configProvider: SignatureClassTypesGridConfigurationService,
                    url: BricataUris.pages.signatureClassTypePage
                },
                {
                    reportId: gridReportIds.referenceTypesReportId,
                    configProvider: ReferenceTypesGridConfigurationService,
                    url: BricataUris.pages.referenceTypesGrid
                },
                {
                    reportId: gridReportIds.signatureSeveritiesReportId,
                    configProvider: SeveritiesGridConfigurationService,
                    url: BricataUris.pages.signatureSeveritiesPage
                },
                {
                    reportId: gridReportIds.signaturesReportId,
                    configProvider: SignaturesGridConfigurationService,
                    url: BricataUris.pages.signaturesPage
                }
            ];

            var getConfigProvider = function(reportId) {
                var configProvider = null;

                for (var i = 0; i < CONFIGURATION_SET.length; i++) {
                    if (CONFIGURATION_SET[i].reportId === reportId) {
                        configProvider = CONFIGURATION_SET[i].configProvider;
                        break;
                    }
                }

                return configProvider;
            };

            var getReportIdMethod = function() {
                var foundReportId = '';

                for (var i = 0; i < CONFIGURATION_SET.length; i++) {
                    if (CommonNavigationService.isThisCurrentLocation(CONFIGURATION_SET[i].url)) {
                        foundReportId = CONFIGURATION_SET[i].reportId;
                        break;
                    }
                }

                return foundReportId;
            };

            var handlerForDataLoadErr = function(reason, errMsg, dataErrProcessor) {
                if (reason.status === 401) {
                    CommonNavigationService.navigateToLoginPage();
                } else {
                    CommonErrorMessageService.showErrorMessage(errMsg, reason, null,
                        dataErrProcessor);
                }
            };

            var getRangeByType = function(type) {
                var ranges = {};


                switch (type) {
                    /* this is not used right now as it was design for "severity" column
                    case 'severity' :
                        ranges = ConfigurationService.getSeverityRanges();
                        break;
                        */
                }

                return ranges;
            };


            var service = {
                setUpGridReportViews:function(gridConfigurationReference){
                    gridConfigurationReference.setConfigProvider(getConfigProvider);
                    gridConfigurationReference.setReportIdMethod(getReportIdMethod);
                    gridConfigurationReference.setDataLoadErrorHandler(handlerForDataLoadErr);
                    gridConfigurationReference.setGridPageSizes(ConfigurationService.getGridPageSizes);
                    gridConfigurationReference.setRangeDetectMethod(getRangeByType);

                    gridConfigurationReference.setGridRequestUrl(BricataUris.gridRequest);
                    gridConfigurationReference.setFilterRequestUrl(BricataUris.filterValueRequest);
                }
            };
            return service;
        }]);