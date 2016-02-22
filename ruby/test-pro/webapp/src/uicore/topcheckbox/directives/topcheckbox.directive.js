angular.module("bricata.uicore.topcheckbox")
    .directive('ngIndeterminate', [ function() {
        return {
            restrict: 'A',
            link: function(scope, element, attributes) {
                scope.$watch(attributes.ngIndeterminate, function (value) {
                    element.prop('indeterminate', !!value);
                });
            }
        };
    }]);