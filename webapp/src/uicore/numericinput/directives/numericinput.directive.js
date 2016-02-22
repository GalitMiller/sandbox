angular.module("bricata.uicore.numericinput")
    .directive("numericInput", [function () {
        return {
            restrict: 'A',
            require: 'ngModel',
            link: function (scope, element, attr, modelCtrl) {

                var min = angular.isDefined(attr.minvalue) ? parseInt(attr.minvalue) : undefined;
                var max = angular.isDefined(attr.maxvalue) ? parseInt(attr.maxvalue) : undefined;

                modelCtrl.$parsers.push(function (inputValue) {
                    var transformedInput = inputValue.replace(/[^\d.-]/g,'');

                    if (transformedInput !== inputValue) {
                        modelCtrl.$setViewValue(transformedInput);
                        modelCtrl.$render();
                    }

                    if (angular.isDefined(min) && parseInt(transformedInput) < min) {
                        transformedInput = '' + min;
                        modelCtrl.$setViewValue(transformedInput);
                        modelCtrl.$render();
                    }

                    if (angular.isDefined(max) && parseInt(transformedInput) > max) {
                        transformedInput = '' + max;
                        modelCtrl.$setViewValue(transformedInput);
                        modelCtrl.$render();
                    }

                    return transformedInput;
                });
            }
        };
    }]);