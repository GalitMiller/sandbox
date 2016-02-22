angular.module("bricata.ui.navigation")
    .value("topMenuLinks", {
        getLinks: function(URIs) {
            return [
                {href: URIs.mainNavLinks.dashboardUrl, name: 'dashboard', type: 'external',
                    isParent :false},
                {href: URIs.mainNavLinks.adminUrl, name: 'administration', type: 'external',
                    isParent: true, children: [
                    {href: URIs.adminButtonDropDownLinks.settingsUrl, name: 'adminButtonLinks.generalSettings',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.classificationsUrl, name: 'adminButtonLinks.classifications',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.sensorsUrl, name: 'adminButtonLinks.sensors',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.lookupUrl, name: 'adminButtonLinks.lookupSources',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.nameManagerUrl, name: 'adminButtonLinks.assetNameManager',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.severitiesUrl, name: 'adminButtonLinks.severities',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.signaturesUrl, name: 'adminButtonLinks.signatures',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.usersUrl, name: 'adminButtonLinks.users',
                        type: 'external'},
                    {href: URIs.adminButtonDropDownLinks.jobQueueUrl, name: 'adminButtonLinks.workerJobQueue',
                        type: 'external'}
                ]},
                {href: URIs.mainNavLinks.sensorsUrl, name: 'sensors', type: 'external',
                    isParent :false},
                {href: URIs.mainNavLinks.signaturesUrl, name: 'signatures', type: 'external',
                    isParent :true,  children: [
                    {href: URIs.signaturesDropDownLinks.signatures, name: 'signaturesButtonLinks.manageGrid',
                        type: 'internal'},
                    {href: URIs.signaturesDropDownLinks.report, name: 'signaturesButtonLinks.report',
                        type: 'external'},
                    {href: URIs.signaturesDropDownLinks.categories, name: 'signaturesButtonLinks.categories',
                        type: 'internal'},
                    {href: URIs.signaturesDropDownLinks.classTypes, name: 'signaturesButtonLinks.classTypes',
                        type: 'internal'},
                    {href: URIs.signaturesDropDownLinks.severities, name: 'signaturesButtonLinks.severities',
                        type: 'internal'},
                    {href: URIs.signaturesDropDownLinks.references, name: 'signaturesButtonLinks.references',
                        type: 'internal'}

                ]},
                {href: URIs.mainNavLinks.policiesUrl, name: 'policies', type: 'internal',
                    isParent :false},
                {href: URIs.mainNavLinks.eventsUrl, name: 'events', type: 'external',
                    isParent :false},
                {href: URIs.mainNavLinks.searchUrl, name: 'search', type: 'external',
                    isParent :false}
            ];
        }
    })
    .value("appRoutes", {
        getLinks: function(URIs) {
            return [
                {url: URIs.pages.policiesPage,
                    template: 'modules/policy/pages/grid.html', default: true},
                {url: URIs.pages.policyWizardPage,
                    template: 'modules/policy/pages/wizard.html'},
                {url: URIs.pages.inactiveSensorPage,
                    template: 'modules/sensors/pages/inactive.html'},
                {url: URIs.pages.signaturesPage,
                    template: 'modules/signature/pages/grid.html'},
                {url: URIs.pages.signatureWizardPage,
                    template: 'modules/signature/pages/wizard.html'},
                {url: URIs.pages.signatureCategoriesPage,
                    template: 'modules/signaturecategories/pages/grid.html'},
                {url: URIs.pages.signatureCategoriesWizardPage,
                    template: 'modules/signaturecategories/pages/wizard.html'},
                {url: URIs.pages.signatureClassTypePage,
                    template: 'modules/signatureclasstypes/pages/grid.html'},
                {url: URIs.pages.signatureClassTypeWizardPage,
                    template: 'modules/signatureclasstypes/pages/wizard.html'},
                {url: URIs.pages.referenceTypesGrid,
                    template: 'modules/referencetype/pages/grid.html'},
                {url: URIs.pages.referenceTypesWizardPage,
                    template: 'modules/referencetype/pages/wizard.html'},
                {url: URIs.pages.signatureSeveritiesPage,
                    template: 'modules/severity/pages/grid.html'},
                {url: URIs.pages.signatureSeveritiesWizardPage,
                    template: 'modules/severity/pages/wizard.html'}
            ];
        }
    });