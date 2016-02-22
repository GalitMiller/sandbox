angular.module("bricata.uicore.validation")
    .directive("referenceInputValidation", ["$i18next", "ValidationService", function($i18next, ValidationService) {
        return {
            restrict: "A",
            scope: {
                rowsModel: "=",
                noDuplicatedReferenceFlag: "="
            },
            link: function(scope, element, attr) {

                element.bind('mouseover', function() {
                    element.off('mouseover');
                    element.bind('click', function() {
                        scope.scheduleValidation();
                    });
                    element.bind('keypress keydown keyup', function() {
                        scope.scheduleValidation();
                    });

                    scope.$watch('rowsModel', function(){
                        scope.scheduleValidation();
                    }, true);

                    scope.scheduleValidation();
                });

                scope.checkTimer = null;
                scope.scheduleValidation = function() {
                    scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
                };

                scope.performValidation = function() {
                    scope.referenceValidationResult = false;
                    for (var i = 0; i < scope.rowsModel.length; i++) {
                        scope.rowsModel[i].isEmpty = false;
                        scope.rowsModel[i].isDuplicated = false;
                    }

                    var emptyReferenceError = scope.searchForEmptyReference();
                    if (emptyReferenceError.length > 0) {
                        ValidationService.showErrorHint(attr, null, element,
                            $i18next(emptyReferenceError));

                        scope.$emit('reference.input.validation.processed', {isValid: false});

                        return;
                    }

                    var duplicatedReferenceError = scope.searchForDuplicatedReference();
                    if (duplicatedReferenceError.length > 0) {
                        ValidationService.showErrorHint(attr, null, element,
                            $i18next(duplicatedReferenceError));

                        scope.$emit('reference.input.validation.processed', {isValid: false});

                        return;
                    }

                    ValidationService.hideErrorHint(attr, null, element);

                    scope.$emit('reference.input.validation.processed', {isValid: true});
                };

                scope.searchForEmptyReference = function() {
                    var errorMsg = "";

                    var entity;
                    for (var i = 0; i < scope.rowsModel.length; i++) {
                        entity = scope.rowsModel[i];

                        if (entity.typeId && entity.value === '' ||
                            scope.rowsModel.length > 1 && entity.typeId === null ||
                            entity.typeId === null && entity.value !== '') {
                            errorMsg = "validationErrors.emptyReferenceValue";
                            entity.isEmpty = true;
                            break;
                        }
                    }

                    return errorMsg;
                };

                scope.searchForDuplicatedReference = function() {
                    var errorMsg = "";
                    scope.noDuplicatedReferenceFlag = true;

                    var entity;
                    var potentialDuplicate;
                    var k;
                    for (var i = 0; i < scope.rowsModel.length; i++) {
                        entity = scope.rowsModel[i];

                        for (k = 0; k < scope.rowsModel.length; k++) {
                            potentialDuplicate = scope.rowsModel[k];

                            if (i !== k && entity.typeId && potentialDuplicate.typeId &&
                                entity.typeId === potentialDuplicate.typeId &&
                                entity.value === potentialDuplicate.value) {
                                errorMsg = "validationErrors.duplicatedReference";
                                entity.isDuplicated = true;
                                potentialDuplicate.isDuplicated = true;
                                scope.noDuplicatedReferenceFlag = false;
                                break;
                            }
                        }

                        if (errorMsg.length > 0) {
                            break;
                        }
                    }

                    return errorMsg;
                };

                var unbindDestroy = scope.$on("$destroy", function() {
                    element.off('click');
                    element.off('keypress keydown keyup');
                    unbindDestroy();
                });
            }
        };
    }]);
