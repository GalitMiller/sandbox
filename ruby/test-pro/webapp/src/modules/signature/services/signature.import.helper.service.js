angular.module('bricata.ui.signature')
    .factory("SignatureImportHelperService", ['CommonErrorMessageService', '$i18next',
        function(CommonErrorMessageService, $i18next) {

            return {
                validateRules: function(rules, isAnySelected) {
                    var isEmptyFound = false;
                    var isDuplicateFound = false;
                    var duplicatedName = '';
                    var problematicRuleId = '';
                    var rulesNameDictionary = {};

                    var rule;
                    for (var i = 0; i < rules.length; i++) {
                        rule = rules[i];

                        if (rule.is_valid) {
                            if (rule.name.length === 0) {
                                isEmptyFound = true;
                                problematicRuleId = '' + i;
                                break;
                            }

                            if (rulesNameDictionary[rule.name]) {
                                duplicatedName = rule.name;
                                problematicRuleId = '' + i;
                                isDuplicateFound = true;
                                break;
                            }

                            rulesNameDictionary[rule.name] = true;
                        }
                    }

                    if (isEmptyFound) {
                        CommonErrorMessageService.showErrorMessage("errors.importValidationEmptyNameError", null,
                            "errors.importValidationFailedTitle");
                    } else if (isDuplicateFound) {
                        CommonErrorMessageService.showErrorMessage($i18next("errors.importValidationDuplicateNameError",
                                { postProcess: 'sprintf', sprintf: [duplicatedName] }), null,
                            "errors.importValidationFailedTitle");
                    } else if (!isAnySelected) {
                        CommonErrorMessageService.showErrorMessage("errors.importValidationNoneSelectedError", null,
                            "errors.importValidationFailedTitle");
                    }

                    return {
                        result: !isEmptyFound && !isDuplicateFound && isAnySelected,
                        pRuleId: problematicRuleId
                    };
                },

                updateTopLvlSettings: function(settingsObj, rules, checkboxItems) {
                    var commonCategory = null;
                    var commonSeverity = null;
                    var isCategoryDifferent = false;
                    var isSeverityDifferent = false;

                    var rule;
                    for (var i = 0; i < rules.length; i++) {
                        rule = rules[i];

                        if (!checkboxItems[rule.uid]) {
                            continue;
                        }

                        if (commonCategory === null) {
                            commonCategory = rule.category;
                        }

                        if (commonSeverity === null) {
                            commonSeverity = rule.severity;
                        }

                        if (commonCategory.id !== rule.category.id) {
                            isCategoryDifferent = true;
                        }

                        if (commonSeverity.id !== rule.severity.id) {
                            isSeverityDifferent = true;
                        }

                        if (isCategoryDifferent && isSeverityDifferent) {
                            break;
                        }
                    }

                    settingsObj.category = isCategoryDifferent ? null : commonCategory;
                    settingsObj.severity = isSeverityDifferent ? null : commonSeverity;
                },

                findEntityById: function(source, lookUpId) {
                    var foundEntity = null;
                    for (var i = 0; i < source.length; i++) {
                        if (source[i].id === lookUpId) {
                            foundEntity = source[i];
                            break;
                        }
                    }

                    return foundEntity;
                }
            };

}]);