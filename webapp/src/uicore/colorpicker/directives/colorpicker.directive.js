angular.module("bricata.uicore.colorpicker")
    .directive("colorPickerCtrl", [
        function () {
            return {
                restrict: 'E',
                templateUrl: 'uicore/colorpicker/views/colorpicker-view.html',
                scope: {
                    selectedColor: "=",
                    validationGroup: "@",
                    validationEventName: "@"
                },
                link: function(scope, element) {
                    var selectedColorRect = angular.element(element[0].querySelector('.color-rect'));

                    var colorPickerInput = angular.element(element[0].querySelector('.color-picker-input'));

                    var txtInput = angular.element(element[0].querySelector('.color-txt-input'));

                    scope.displaySelectedColor = function() {
                        selectedColorRect[0].style.backgroundColor = scope.selectedColor;
                    };

                    selectedColorRect.on('click', function() {
                        colorPickerInput.triggerHandler('click');
                    });

                    txtInput.on('click', function() {
                        colorPickerInput.triggerHandler('click');
                    });

                    scope.displaySelectedColor();

                    scope.$watch('selectedColor', function() {
                        scope.displaySelectedColor();
                    });

                }
            };
        }]);