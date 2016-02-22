angular.module("bricata.uicore.notification")
    .directive("systemNotification", [
        function () {
            return {
                restrict: 'E',
                templateUrl: 'uicore/notification/views/notification-view.html',
                scope: {
                    msgTxt: '=',
                    btnLbl: '@',
                    btnAction: '&',
                    isNotificationShown: "="
                },
                link: function(scope) {
                    scope.closeNotification = function() {
                        scope.isNotificationShown = false;
                    };

                    scope.handleBtnClick = function() {
                        scope.btnAction()();
                        scope.closeNotification();
                    };
                }
            };
        }]);