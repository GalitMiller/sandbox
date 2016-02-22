angular.module('bricata.ui.api', [])
    .factory('BricataUris', [function(){
        var SPA_PAGES = {
            policiesPage: '/policies',
            policyWizardPage: '/policies/wizard',
            inactiveSensorPage: '/sensors/inactive',
            signaturesPage: '/signatures',
            signatureWizardPage: '/signatures/wizard',
            signatureCategoriesPage: '/signatures/categories',
            signatureCategoriesWizardPage: '/signatures/categories/wizard',
            signatureClassTypePage: '/signatures/classtypes',
            signatureClassTypeWizardPage: '/signatures/classtypes/wizard',
            referenceTypesGrid: '/signatures/references',
            referenceTypesWizardPage: '/signatures/references/wizard',
            signatureSeveritiesPage: '/signatures/severities',
            signatureSeveritiesWizardPage: '/signatures/severities/wizard'
        };

        return {
            configurationUrl: 'config/app_conf.json',

            userInfo: 'json-mocks/userinfo.json',
            gridRequest: 'json-mocks/:entityId?page=:page&results_per_page=:pagesize&q=:query',
            filterValueRequest: 'json-mocks/:entityId',

            policyItems: 'policies.json',
            policyItem: 'json-mocks/policies.json:id',
            policyNames: 'json-mocks/policies.json',
            policyGridFilterValues: 'authors.json',
            policyApplication: '../api/v1/sensors/interfaces/apply_policies',
            policyAppliedInfo: 'json-mocks/policy.applied_:id.json',
            policyPreviewAction: '_preview.json',

            signatureCategories: 'json-mocks/signatures.categories.lite.json',
            signatureClassTypes: 'json-mocks/signature.class.types.json',
            signatureReferenceTypes: 'json-mocks/signature.reference.types.json',
            signatureSeverity: 'json-mocks/signature.severities.json',
            sidIDNumber: 'json-mocks/new_sid.json',
            sendSignatureForPreview: 'json-mocks/preview.json',
            signatureImportPreview: 'json-mocks/import_preview.json',
            signatureImportUpload: 'json-mocks/signature.import.result.json',
            signatureProtocols: 'json-mocks/signature.protocols.json',
            signatureMappingItem: 'json-mocks/signature.mapping.json',

            signaturesList: 'signatures.list.json',
            signaturesGridFilterValues: 'authors.json',
            signaturesItem: 'json-mocks/signatures.item.json',
            signaturesRules: 'json-mocks/signatures.details.json',
            signatureCategoriesList: 'signatures.categories.json',
            signatureCategoryItem: 'json-mocks/signatures.categories.item.json',
            signatureCategorySignatures: 'json-mocks/policy.detail.signatures.json',
            signatureSearchedItems: '../result',
            signatureExport: 'json-mocks/signatures.item.json',
            signatureCategoriesUpdates: 'json-mocks/signatures.categories.lite.json',

            signatureClassTypesGrid: 'signature.class.types.json',
            signatureClassTypeItem: 'json-mocks/signature.class.types.item.json',
            signatureClassTypeImportUpload: 'json-mocks/reference.import.json',
            signatureClassTypeExport: 'json-mocks/signature.reference.types.json',

            sensorsControlled: 'json-mocks/sensorsControlled.json',
            sensorItems: 'json-mocks/sensors.json',
            interfaceItems: 'json-mocks/interfaces.json?q=:rowId',
            inactiveSensorItems: 'inactive.sensors.json',
            inactiveSensorItemCount: 'json-mocks/inactive.sensors.count.json',
            sensorControlItem: 'json-mocks/sensor.activated.json?:id',

            policyDetailRequest: 'json-mocks/:entityId?q=:rowId',
            policyDetailSensors: 'policy.detail.sensors.json',
            policyDetailSignatures: 'policy.detail.signatures.json',

            referenceTypeList: 'signature.reference.types.json',
            referenceTypeItem: 'json-mocks/signature.reference.types.json',
            referenceImportUpload: 'json-mocks/reference.import.json',
            referenceExport: 'json-mocks/signatures.item.json',

            severityList: 'signature.severities.json',
            severityItem: 'json-mocks/signature.severities.json',

            // Main Navigation Links
            loginPageLink: '../users/login',
            logoutPageLink: '../users/logout',
            settingsPageLink: '../users/edit',
            logoLink: '../',

            pages: SPA_PAGES,

            // The 'name' values are set in the bundle_en.json file
            mainNavLinks: {
                dashboardUrl: 'http://google.com',
                adminUrl: 'administration',
                sensorsUrl: 'sensors',
                signaturesUrl: 'signatures',
                policiesUrl: SPA_PAGES.policiesPage,
                eventsUrl: 'events',
                searchUrl: 'search'
            },

            // Administration button drop-down menu links
            // The 'name' values are set in the bundle_en.json file
            adminButtonDropDownLinks: {
                settingsUrl: 'http://google.com',
                classificationsUrl: 'classifications',
                sensorsUrl: 'sensors',
                lookupUrl: 'lookup-sources',
                nameManagerUrl: 'asset-name-manager',
                severitiesUrl: 'severities',
                signaturesUrl: 'signatures',
                usersUrl: 'users',
                jobQueueUrl: 'worker-job-queue'
            },

            signaturesDropDownLinks: {
                signatures: SPA_PAGES.signaturesPage,
                report: 'signatures',
                categories: SPA_PAGES.signatureCategoriesPage,
                classTypes: SPA_PAGES.signatureClassTypePage,
                references: SPA_PAGES.referenceTypesGrid,
                severities: SPA_PAGES.signatureSeveritiesPage
            }

        };
    }]);