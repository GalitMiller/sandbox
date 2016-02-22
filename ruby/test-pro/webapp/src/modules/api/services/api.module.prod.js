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

            userInfo: '../api/v1/current_user',
            gridRequest: '../api/v1/:entityId?page=:page&results_per_page=:pagesize&q=:query',
            filterValueRequest: '../api/v1/:entityId',

            policyItems: 'policies',
            policyItem: '../api/v1/policies:id',
            policyNames: '../api/v1/policies/lite',
            policyGridFilterValues: 'users',
            policyApplication: '../api/v1/sensors/interfaces/apply_policies',
            policyAppliedInfo: '../api/v1/sensors/interfaces/:id/applied_policies',
            policyPreviewAction: '/preview',

            signatureCategories: '../api/v1/signature_categories/lite',
            signatureClassTypes: '../api/v1/signature_class_types',
            signatureReferenceTypes: '../api/v1/reference_types',
            signatureSeverity: '../api/v1/signature_severities',
            sidIDNumber: '../api/v1/signatures/new_sid',
            sendSignatureForPreview: '../api/v1/signatures/preview',
            signatureImportPreview: '../api/v1/signatures/import/preview',
            signatureImportUpload: '../api/v1/signatures/import',
            signatureProtocols: '../api/v1/signature_protocols',
            signatureMappingItem: '../api/v1/snorby_signatures/by_sid/:id/ids',

            signaturesList: 'signatures/lite',
            signaturesGridFilterValues: 'users',
            signaturesItem: '../api/v1/signatures/:id',
            signaturesRules: '../api/v1/signatures/:id/rule',
            signatureCategoriesList: 'signature_categories',
            signatureCategoryItem: '../api/v1/signature_categories/:id',
            signatureCategorySignatures: '../api/v1/signature_categories/:id/signatures',
            signatureSearchedItems: '../results',
            signatureExport: '../api/v1/signatures/export',
            signatureCategoriesUpdates: '../api/v1/signature_categories/updates',

            signatureClassTypesGrid: 'signature_class_types',
            signatureClassTypeItem: '../api/v1/signature_class_types/:id',
            signatureClassTypeImportUpload: '../api/v1/signature_class_types/import',
            signatureClassTypeExport: '../api/v1/signature_class_types/export',

            sensorsControlled: '../api/v1/sensors/controlled',
            sensorItems: '../api/v1/sensors',
            interfaceItems: '/api/v1/sensors/:rowId/interfaces/refresh?conn_timeout=10',
            inactiveSensorItems: 'sensors/uncontrolled',
            inactiveSensorItemCount: '../api/v1/sensors/uncontrolled/count',
            sensorControlItem: '../api/v1/sensors/:id/take_control',

            policyDetailRequest: '../api/v1/policies/:rowId/:entityId',
            policyDetailSensors: 'applications',
            policyDetailSignatures: 'signatures/lite',

            referenceTypeList: 'reference_types',
            referenceTypeItem: '../api/v1/reference_types/:id',
            referenceImportUpload: '../api/v1/reference_types/import',
            referenceExport: '../api/v1/reference_types/export',

            severityList: 'signature_severities',
            severityItem: '../api/v1/signature_severities/:id',

            // Main Navigation Links
            loginPageLink: '../users/login',
            logoutPageLink: '../users/logout',
            settingsPageLink: '../users/edit',
            logoLink: '../',

            pages: SPA_PAGES,

            // The 'name' values are set in the bundle_en.json file
            mainNavLinks: {
                dashboardUrl: '../dashboard',
                adminUrl: 'administration',
                sensorsUrl: '../sensors',
                signaturesUrl: 'signatures',
                policiesUrl: SPA_PAGES.policiesPage,
                eventsUrl: '../events/sessions',
                searchUrl: '../search'
            },

            // Administration button drop-down menu links
            // The 'name' values are set in the bundle_en.json file
            adminButtonDropDownLinks: {
                settingsUrl: '../settings',
                classificationsUrl: '../classifications',
                sensorsUrl: '../sensors',
                lookupUrl: '../lookups',
                nameManagerUrl: '../asset_names',
                severitiesUrl: '../severities',
                signaturesUrl: '../signatures',
                usersUrl: '../users',
                jobQueueUrl: '../jobs'
            },

            signaturesDropDownLinks: {
                signatures: SPA_PAGES.signaturesPage,
                report: '../signatures',
                categories: SPA_PAGES.signatureCategoriesPage,
                classTypes: SPA_PAGES.signatureClassTypePage,
                references: SPA_PAGES.referenceTypesGrid,
                severities: SPA_PAGES.signatureSeveritiesPage
            }

        };
    }]);