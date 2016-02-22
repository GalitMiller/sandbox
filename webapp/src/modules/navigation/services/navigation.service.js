angular.module('bricata.ui.navigation')
    .service('CommonNavigationService',
    ['$window', '$location', 'BricataUris', '$route', 'appRoutes', 'CommonProxyForRequests',
        function($window, $location, BricataUris, $route, appRoutes, CommonProxyForRequests){

            this.navigateTo = function (url, linkType, searchObject) {
                switch (linkType) {
                    case 'external':
                        $window.location.href = url;
                        break;
                    case 'internal':
                        CommonProxyForRequests.cancelAllPendingRequests();
                        if (searchObject) {
                            $location.path(url).search(searchObject);
                        } else {
                            $location.path(url);
                        }
                        break;
                }
            };

            this.isThisCurrentLocation = function(currentLinkPart) {
                return $location.absUrl().indexOf(currentLinkPart) > 0;
            };

            this.navigateToPoliciesGridPage = function() {
                this.navigateTo(BricataUris.pages.policiesPage, 'internal');
            };

            this.navigateToPolicyWizardPage = function() {
                this.navigateTo(BricataUris.pages.policyWizardPage, 'internal');
            };

            this.navigateToInactiveSensorsGridPage = function() {
                this.navigateTo(BricataUris.pages.inactiveSensorPage, 'internal');
            };

            this.navigateToSignaturesGridPage = function() {
                this.navigateTo(BricataUris.pages.signaturesPage, 'internal');
            };

            this.navigateToSignatureWizardPage = function() {
                this.navigateTo(BricataUris.pages.signatureWizardPage, 'internal');
            };

            this.navigateToSignatureCategoriesGridPage = function() {
                this.navigateTo(BricataUris.pages.signatureCategoriesPage, 'internal');
            };

            this.navigateToSignatureCategoriesWizardPage = function() {
                this.navigateTo(BricataUris.pages.signatureCategoriesWizardPage, 'internal');
            };

            this.navigateToSignatureClassTypeWizardPage = function() {
                this.navigateTo(BricataUris.pages.signatureClassTypeWizardPage, 'internal');
            };

            this.navigateToSignatureClassTypePage = function() {
                this.navigateTo(BricataUris.pages.signatureClassTypePage, 'internal');
            };

            this.navigateToReferenceTypeGridPage = function() {
                this.navigateTo(BricataUris.pages.referenceTypesGrid, 'internal');
            };

            this.navigateToReferenceTypeWizardPage = function() {
                this.navigateTo(BricataUris.pages.referenceTypesWizardPage, 'internal');
            };

            this.navigateToSeverityGridPage = function() {
                this.navigateTo(BricataUris.pages.signatureSeveritiesPage, 'internal');
            };

            this.navigateToSeverityWizardPage = function() {
                this.navigateTo(BricataUris.pages.signatureSeveritiesWizardPage, 'internal');
            };

            this.navigateToLoginPage = function() {
                this.navigateTo(BricataUris.loginPageLink, 'external');
            };

            //in future it will be easy to exclude some routes basing on user roles, just add logic below
            this.setupNavigation = function(routerProviderReference) {
                var pages = appRoutes.getLinks(BricataUris);
                for (var i = 0; i < pages.length; i++) {
                    routerProviderReference
                        .when(pages[i].url,{
                            templateUrl: pages[i].template
                        });

                    if (pages[i].default) {
                        routerProviderReference.otherwise({ redirectTo: pages[i].url });
                    }
                }

                $route.reload();
            };

        }]);
