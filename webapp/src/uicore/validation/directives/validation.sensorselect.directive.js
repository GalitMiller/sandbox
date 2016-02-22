angular.module("bricata.uicore.validation")
    .directive("sensorSelectValidation", ["$i18next", "$rootScope", "ValidationService",
        function($i18next, $rootScope, ValidationService) {
            return {
                restrict: "A",
                scope: {
                    rowsModel: "=",
                    duplicatedFlag: "=",
                    topLvlErrMsgUpdate: "&"
                },
                link: function(scope, element, attr) {

                    scope.listenersAttached = false;

                    var unbindRootScopeListener = $rootScope.$on('run.validation', function() {
                        scope.addValidationListeners();
                        ValidationService.showTooltip(element.parent().parent());
                    });

                    element.bind('mouseover', function() {
                        scope.addValidationListeners();
                    });

                    scope.addValidationListeners = function() {
                        if (!scope.listenersAttached) {
                            scope.listenersAttached = true;
                            element.off('mouseover');

                            scope.$watch('rowsModel', function(){
                                scope.scheduleValidation();
                            }, true);

                            element.bind('mouseover', function() {
                                ValidationService.showTooltip(element.parent().parent());
                            });

                            scope.scheduleValidation();
                        }
                    };

                    scope.checkTimer = null;
                    scope.scheduleValidation = function() {
                        scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
                    };

                    scope.performValidation = function() {
                        for (var i = 0; i < scope.rowsModel.length; i++) {
                            scope.rowsModel[i].isEmpty = false;
                            scope.rowsModel[i].isDuplicated = false;
                        }
                        var emptyError = scope.searchForEmpty();
                        if (emptyError.length > 0) {
                            scope.topLvlErrMsgUpdate()($i18next(emptyError));

                            ValidationService.showErrorHint(attr, null, element.parent().parent(),
                                $i18next(emptyError), true);

                            scope.$emit('sensors.select.validation.processed',
                                {isValid: false});

                            return;
                        }

                        var duplicatesError = scope.searchForDuplicates();
                        if (duplicatesError.length > 0) {
                            scope.topLvlErrMsgUpdate()($i18next(duplicatesError));
                            ValidationService.showErrorHint(attr, null, element.parent().parent(),
                                $i18next(duplicatesError), true);

                            scope.$emit('sensors.select.validation.processed',
                                {isValid: false});

                            return;
                        }

                        scope.topLvlErrMsgUpdate()('');
                        ValidationService.hideErrorHint(attr, null, element.parent().parent(), true);

                        scope.$emit('sensors.select.validation.processed',
                            {isValid: true});
                    };

                    scope.searchForEmpty = function() {
                        var errorMsg = "";

                        var entity;
                        for (var i = 0; i < scope.rowsModel.length; i++) {
                            entity = scope.rowsModel[i];

                            if (!angular.isDefined(entity.sensor.name) || entity.sensor.name === '' ||
                                !angular.isDefined(entity.interface.name) || entity.interface.name === '') {
                                errorMsg = "validationErrors.errorEmptyCompositeInput";
                                entity.isEmpty = true;
                                break;
                            }
                        }

                        return errorMsg;
                    };

                    scope.searchForDuplicates = function() {
                        var errorMsg = "";
                        scope.duplicatedFlag = false;

                        var entity;
                        var potentialDuplicate;
                        var k;
                        for (var i = 0; i < scope.rowsModel.length; i++) {
                            entity = scope.rowsModel[i];

                            for (k = 0; k < scope.rowsModel.length; k++) {
                                potentialDuplicate = scope.rowsModel[k];

                                if (i !== k && entity.sensor.name === potentialDuplicate.sensor.name &&
                                    entity.interface.name === potentialDuplicate.interface.name) {
                                    errorMsg = "applyPolicyModal.errorDuplicatedInterfaces";
                                    entity.isDuplicated = true;
                                    potentialDuplicate.isDuplicated = true;
                                    scope.duplicatedFlag = true;
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
                        unbindRootScopeListener();
                        element.off('mouseover');
                        unbindDestroy();
                    });
                }
            };
        }]);
