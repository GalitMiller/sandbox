angular.module("bricata.uicore.validation")
    .directive("signatureSelectValidation", ["$rootScope", "$i18next", "ValidationService",
        function($rootScope, $i18next, ValidationService) {
        return {
            restrict: "A",
            link: function(scope, element, attr) {

                scope.listenersAttached = false;

                var unbindRootScopeListener = $rootScope.$on('run.validation', function(event, data) {
                    if (data && data.group) {
                        return;
                    }
                    scope.addValidationListeners();
                });

                var unbindLengthWatch = scope.$watch('selectionModel.length', function() {
                    if (scope.selectionModel.length > 0) {
                        scope.addValidationListeners();
                    }
                });

                scope.addValidationListeners = function() {
                    if (!scope.listenersAttached) {
                        scope.listenersAttached = true;
                        unbindLengthWatch();

                        scope.$watch('selectionModel.length', scope.scheduleValidation);
                        scope.scheduleValidation();
                    }
                };

                scope.checkTimer = null;
                scope.scheduleValidation = function() {
                    scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
                };

                var unbindRootScopeListenerForDisable = $rootScope.$on('disable.validation', function() {
                    ValidationService.pauseValidation(element);
                });

                var unbindRootScopeListenerForEnable = $rootScope.$on('enable.validation', function() {
                    ValidationService.resumeValidation(element);
                });

                scope.performValidation = function() {
                    var validationResult = false;

                    if (scope.selectionModel.length === 0) {
                        ValidationService.showErrorHint(attr, element.parent(), element,
                            $i18next('validationErrors.noSignaturesSelected'));
                    } else {
                        ValidationService.hideErrorHint(attr, element.parent(), element);

                        validationResult = true;
                    }

                    scope.$emit('signature.select.validation.processed',
                        {isValid: validationResult});
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
