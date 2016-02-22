angular.module("bricata.uicore.labletrunc")
    .directive("labelTrunc", [function() {
        return {
            restrict: "A",
            scope: {},

            link: function(scope, element, attr) {

                scope.updateTooltip = function() {
                    attr.$set('tooltip', '');
                    var fullTextElem = element
                        .clone()
                        .css({display: 'inline', width: 'auto', visibility: 'hidden'});
                    element.parent().append(fullTextElem);

                    if (fullTextElem[0].offsetWidth > element[0].offsetWidth) {
                        attr.$set('tooltip', element.html());
                    }

                    fullTextElem.remove();
                };

                /*$timeout(function(){
                 scope.updateTooltip();
                 }, 333, false);*/
                element.bind('mouseover', function(event) {
                    event.preventDefault();
                    event.stopPropagation();

                    scope.updateTooltip();
                    element.triggerHandler('mouseenter');
                });

                var unbindDestroy = scope.$on("$destroy", function() {
                    element.off('mouseover');
                    unbindDestroy();
                });

            }
        };
    }]);
