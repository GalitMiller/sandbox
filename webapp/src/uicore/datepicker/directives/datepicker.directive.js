angular.module("bricata.uicore.datepicker")
    .directive("commonDatePicker", [
        function() {
            return {
                restrict : 'EA',
                templateUrl : 'uicore/datepicker/views/common-date-picker.html',
                scope: {
                    dateOptions: "=",
                    minDate: "=",
                    maxDate: "=",
                    dateChanged: "&",
                    dt: "="
                },
                link: function(scope) {
                    scope.today = function() {
                        scope.dt = new Date();
                    };

                    scope.clear = function () {
                        scope.dt = null;
                    };

                    scope.toggleMin = function() {
                        scope.dt = scope.minDate;
                    };

                    scope.$watch('dt', function() {
                        var valueToPass = null;
                        if (scope.dt) {
                            valueToPass = scope.dt;
                        }
                        scope.dateChanged()(valueToPass);
                    });

                    scope.open = function($event) {
                        $event.preventDefault();
                        $event.stopPropagation();

                        scope.opened = !scope.opened;
                    };

                }
            };
        }]);