angular.module('bricata.uicore.preloader')
    .directive('loadingContainer', ["$compile", function($compile) {
        return {
            restrict: 'A',
            scope: false,
            link: function(scope, element, attrs) {
                scope.progress = 0;
                var loadingLayer = $compile('<div class="loading">'+
                    '<preloader additional-class="preloader-repositioned" progress-value="progress">' +
                    '</preloader></div>')(scope);
                element.append(loadingLayer);
                element.addClass('loading-container');
                scope.$watch(attrs.loadingContainer, function(value) {
                    loadingLayer.toggleClass('ng-hide', !value);
                });

                scope.$watch(attrs.loadingProgress, function(value) {
                    scope.progress = value;
                });
            }
        };
    }]);
