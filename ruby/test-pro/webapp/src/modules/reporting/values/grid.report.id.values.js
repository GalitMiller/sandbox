angular.module("bricata.ui.reporting")
    .value("gridReportIds", {
        policyReportId: "policies",
        inactiveSensorsReportId: "inactive-sensors",
        signaturesReportId: "signatures",
        signatureCategoriesReportId: "signatures-categories",
        signatureClassTypesReportId: "signatures-class-types",
        referenceTypesReportId: "reference-types",
        signatureSeveritiesReportId: "signatures-severities"
    });