angular.module("bricata.uicore.scrollspy")
    .directive('scrollSpy', [function() {
        return {
            restrict: 'A',
            scope: {
                vScrollPos: "=",
                scrollHeight: "=",
                scrollHandler: "&"
            },
            link: function(scope, element) {
                var scrollElem = angular.element(element[0].querySelector('.scrollable-content'))[0];

                scope.$watch("vScrollPos", function() {
                    if ((scrollElem.offsetHeight - scope.scrollHeight - scope.scrollHeight*0.2) < scope.vScrollPos) {
                        scope.scrollHandler()();
                    }
                });

                scope.$on('scroll.to.element.id', function(event, data) {
                    var elementOffset = angular.element(element[0].querySelector(data.elementId))[0].offsetTop;

                    scope.vScrollPos = elementOffset;
                });
            }
        };
    }]);