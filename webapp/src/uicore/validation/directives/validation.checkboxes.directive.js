angular.module("bricata.uicore.validation")
    .directive("checkboxesValidation", ["$i18next", "$rootScope", "ValidationService",
        function($i18next, $rootScope, ValidationService) {
        return {
            restrict: "A",
            scope: {
                validationEventName: '@'
            },
            link: function(scope, element, attr) {

                scope.listenersAttached = false;

                var unbindRootScopeListener = $rootScope.$on('run.validation', function() {
                    scope.addValidationListeners();
                });

                element.bind('mouseover', function() {
                    scope.addValidationListeners();
                });

                scope.addValidationListeners = function() {
                    if (!scope.listenersAttached) {
                        scope.listenersAttached = true;
                        element.off('mouseover');

                        element.bind('click', function() {
                            scope.scheduleValidation();
                        });

                        scope.scheduleValidation();
                    }
                };

                scope.checkTimer = null;
                scope.scheduleValidation = function() {
                    scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
                };

                scope.performValidation = function() {
                    var validationResult = false;
                    var checkboxes = element[0].querySelectorAll('[type="checkbox"]');
                    var isAnyChecked = false;

                    var checkbox;
                    for (var i = 0; i < checkboxes.length; i++) {
                        checkbox = checkboxes[i];

                        if (checkbox.checked) {
                            isAnyChecked = true;
                            break;
                        }
                    }

                    if (isAnyChecked) {
                        ValidationService.hideErrorHint(attr, element, element);

                        validationResult = true;
                    } else {
                        ValidationService.showErrorHint(attr, element, element,
                            $i18next('validationErrors.checkboxesNotSelected'));
                    }

                    scope.$emit('checkboxes.validation.processed',
                        {name: scope.validationEventName, isValid: validationResult});
                };

                var unbindDestroy = scope.$on("$destroy", function() {
                    unbindRootScopeListener();
                    element.off('click');
                    unbindDestroy();
                });
            }
        };
    }]);
