angular.module("bricata.uicore.preloader")
    .directive("preloader", [
        function () {
            return {
                restrict: 'E',
                templateUrl: 'uicore/preloader/views/preloader.html',
                scope: {
                  textBundleKey: "@",
                  additionalClass: "@",
                  progressValue: "="
                }
            };
        }]);