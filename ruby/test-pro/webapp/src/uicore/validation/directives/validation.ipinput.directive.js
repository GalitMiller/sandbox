angular.module("bricata.uicore.validation")
    .directive("ipInputValidation", ["$i18next", "ValidationService", "$rootScope",
        function($i18next, ValidationService, $rootScope) {
        return {
            restrict: "A",
            link: function(scope, element, attr) {

                var unbindRootScopeListener = $rootScope.$on('run.validation', function() {
                    scope.scheduleValidation();
                });

                scope.$on('input.text.validation.processed', function() {
                    scope.scheduleValidation();
                });

                element.bind('click', function() {
                    scope.scheduleValidation();
                    element.off('click');
                });

                scope.checkTimer = null;
                scope.scheduleValidation = function() {
                    scope.checkTimer = ValidationService.validateLater(scope.checkTimer, scope.performValidation);
                };

                /*

                scope.validateIpValueThroughRegExp = function() {

                    var validationPassed = true;

                    var ipv4Pattern = RegExp(['^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]',
                        '|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'].join(''));

                    var ipv4CIDRPattern = RegExp(['^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]',
                            '|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$'].join(''));

                    var ipv6Pattern = RegExp(['^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:)',
                            '{6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d))',
                            '{3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:)',
                            '{4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}',
                            '(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)',
                            '(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]',
                            '{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)',
                            '(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4})',
                            '{1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]',
                            '|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*'].join(''));

                    var ipv6CIDRPattern =
                        RegExp(['^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:)',
                            '{6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d))',
                            '{3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]',
                            '{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)',
                            '(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]',
                            '{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]',
                            '|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4})',
                            '{1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]',
                            '{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))',
                            '|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|',
                            '[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))',
                            '|:)))(%.+)?s*(\\/(d|dd|1[0-1]d|12[0-8]))$'].join(''));


                    if (ipv4Pattern.test(scope.selectedIpAddress.ip.address) ||
                        ipv4CIDRPattern.test(scope.selectedIpAddress.ip.address) ||
                        ipv6Pattern.test(scope.selectedIpAddress.ip.address) ||
                        ipv6CIDRPattern.test(scope.selectedIpAddress.ip.address)) {

                        validationPassed = false;
                    }

                    return validationPassed;

                };

                */

                scope.performValidation = function() {

                    var validationResult = false;

                    if (scope.selectedIpAddress.ip === '' && !scope.selectedIpAddress.anyIp) {
                        ValidationService.showErrorHint(attr, null, element,
                            $i18next('validationErrors.ipValueIsEmpty'));
                    } else if (scope.selectedPort.port === '' && !scope.selectedPort.anyPort) {
                        ValidationService.showErrorHint(attr, null, element,
                            $i18next('validationErrors.portValueIsEmpty'));

                        /*
                    } else if (!scope.selectedIpAddress.anyIp && scope.validateIpValueThroughRegExp()) {
                        attr.$set('tooltip', $i18next('IP Address is not valid'));
                        element.triggerHandler('validationfailed');
                        */

                    } else {
                        ValidationService.hideErrorHint(attr, null, element);

                        if ((scope.selectedIpAddress.ip.length > 0 || scope.selectedIpAddress.anyIp) &&
                            (scope.selectedPort.port.length > 0  || scope.selectedPort.anyPort)) {

                            validationResult = true;
                        }
                    }

                    scope.$emit('ip.input.validation.processed',
                        {name: scope.topValidationResultName, isValid: validationResult});
                };

                var unbindDestroy = scope.$on("$destroy", function() {
                    unbindRootScopeListener();
                    unbindDestroy();
                });
            }
        };
    }]);
