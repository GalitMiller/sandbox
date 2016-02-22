angular.module("bricata.uicore.labletrunc")
    .directive("labelTruncPostponed", ["$timeout", function($timeout) {
        return {
            restrict: "A",
            scope: {
                isDisplayed: '='
            },

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

                var unbindWatch = scope.$watch('isDisplayed', function() {
                    if (scope.isDisplayed) {
                        unbindWatch();
                        $timeout(function(){
                            scope.updateTooltip();
                        }, 333, false);
                    }
                });
            }
        };
    }]);
