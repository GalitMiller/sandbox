angular.module("bricata.uicore.validation")
    .directive("colorPickerValidation", ["$i18next", "$rootScope", "ValidationService",
        function($i18next, $rootScope, ValidationService) {
            return {
                restrict: "A",
                scope: false,
                link: function(scope, element, attr) {

                    var colorPattern = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;

                    scope.listenersAttached = false;

                    var unbindRootScopeListener = $rootScope.$on('run.validation', function(event, data) {
                        if (data && data.group) {
                            if (angular.isDefined(scope.validationGroup) && scope.validationGroup === data.group) {
                                scope.addValidationListeners();
                            }
                        } else {
                            scope.addValidationListeners();
                        }
                    });

                    element.bind('blur', function() {
                        scope.addValidationListeners();
                    });

                    var unbindValueWatch = scope.$watch(function() { return scope.selectedColor; },
                        function() {
                            if (scope.selectedColor && scope.selectedColor.length > 0) {
                                scope.addValidationListeners();
                            }
                        });

                    scope.addValidationListeners = function() {
                        if (!scope.listenersAttached) {
                            element.off('blur');
                            unbindValueWatch();
                            scope.listenersAttached = true;

                            scope.$watch(function() {return scope.selectedColor;},
                                scope.scheduleValidation);

                            scope.scheduleValidation();
                        }
                    };

                    scope.checkTimer = null;
                    scope.scheduleValidation = function() {
                        scope.checkTimer = ValidationService.validateLater(scope.checkTimer,
                            scope.performValidation);
                    };

                    scope.setTooltip = '';
                    var unbindRootScopeListenerForDisable = $rootScope.$on('disable.validation', function() {
                        ValidationService.pauseValidation(element);
                    });

                    var unbindRootScopeListenerForEnable = $rootScope.$on('enable.validation', function() {
                        ValidationService.resumeValidation(element);
                    });

                    scope.performValidation = function() {
                        var result = false;

                        if (!scope.selectedColor || scope.selectedColor.length === 0) {
                            ValidationService.showErrorHint(attr, element, element,
                                $i18next('validationErrors.fieldRequired'));
                        } else if (!colorPattern.test(scope.selectedColor)) {
                            ValidationService.showErrorHint(attr, element, element,
                                $i18next('validationErrors.incorrectValue'));
                        } else {
                            ValidationService.hideErrorHint(attr, element, element);

                            result = true;
                        }

                        if (angular.isDefined(scope.validationResult)) {
                            scope.validationResult = result;
                        }

                        if (angular.isDefined(scope.validationEventName)) {
                            scope.$emit('input.text.validation.processed',
                                {name: scope.validationEventName, isValid: result});
                        } else {
                            scope.$emit('input.text.validation.processed');
                        }

                    };

                    var unbindDestroy = scope.$on("$destroy", function() {
                        unbindRootScopeListener();
                        unbindRootScopeListenerForDisable();
                        unbindRootScopeListenerForEnable();
                        unbindDestroy();
                    });

                }
            };
        }]);
