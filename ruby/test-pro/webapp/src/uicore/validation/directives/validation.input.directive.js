angular.module("bricata.uicore.validation")
    .directive("inputValidation", ["$i18next", "$rootScope", "ValidationService",
        function($i18next, $rootScope, ValidationService) {
        return {
            restrict: "A",
            scope: {
              validationEventName: '@',
              validationResult: '=',
              validationGroup: '@'
            },
            link: function(scope, element, attr) {

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

                var unbindValueWatch = scope.$watch(function() { return element.val(); }, function() {
                    if (element.val().trim().length > 0 && element.val().trim() !== '?') {
                        scope.addValidationListeners();
                    }
                });

                var unbindDisabledWatch = scope.$watch(function() { return element.prop('disabled'); }, function() {
                    if (element.prop('disabled') === true) {
                        scope.addValidationListeners();
                    }
                });

                scope.addValidationListeners = function() {
                    if (!scope.listenersAttached) {
                        element.off('blur');
                        unbindValueWatch();
                        unbindDisabledWatch();
                        scope.listenersAttached = true;

                        scope.$watch(function() { return element.val(); }, scope.scheduleValidation);

                        scope.$watch(function() { return element.prop('disabled'); }, scope.scheduleValidation);

                        scope.scheduleValidation();
                    }
                };

                scope.checkTimer = null;
                scope.scheduleValidation = function() {
                    scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
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

                    var trimmedValue = element.val().trim();

                    if (attr.required && (trimmedValue.length === 0 || trimmedValue === '?')) {
                        ValidationService.showErrorHint(attr, element.parent(), element,
                            $i18next('validationErrors.fieldRequired'));
                    } else if (attr.ngMinlength > 0 && trimmedValue.length < attr.ngMinlength) {
                        ValidationService.showErrorHint(attr, element.parent(), element,
                            $i18next('validationErrors.tooSmall',
                                { postProcess: 'sprintf', sprintf: [attr.ngMinlength] }));
                    } else if (attr.ngMaxlength > 0 && trimmedValue.length > attr.ngMaxlength) {
                            ValidationService.showErrorHint(attr, element.parent(), element,
                                $i18next('validationErrors.tooLong',
                                    { postProcess: 'sprintf', sprintf: [attr.ngMaxlength] }));
                    } else if (!element.prop('disabled') && attr.ngPattern && !attr.ngPattern.test(trimmedValue)) {

                        var errorMessage;

                        if (element.attr('custom-tooltip') && element.attr('custom-tooltip').length){
                            errorMessage = element.attr('custom-tooltip');
                        } else {
                            errorMessage = $i18next('validationErrors.incorrectValue');
                        }

                        ValidationService.showErrorHint(attr, element.parent(), element,
                            errorMessage);
                    } else {
                        ValidationService.hideErrorHint(attr, element.parent(), element);

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
