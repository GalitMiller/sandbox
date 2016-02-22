angular.module("bricata.uicore.select")
    .directive("commonSelect", ["$templateCache", "$compile",
        function($templateCache, $compile) {
            return {
                restrict : 'EA',
                scope: {
                    lblField: '@',
                    ngModel: '=',
                    ngChange: '&',
                    ngOptions: '=',
                    parentRow: '=',
                    updateParentRow: '&',
                    isPlainTxt: '@',
                    placeholder: '@',
                    validationEnabled: '@',
                    validationEventName: '@',
                    validationResult: '=',
                    validationGroup: '@',
                    appendToBody: '@'
                },
                link: function(scope, element, attr) {
                    scope.opened = false;
                    scope.isStyleSet = false;

                    scope.open = function($event) {
                        $event.preventDefault();
                        $event.stopPropagation();
                        if (!scope.isStyleSet) {
                            scope.innerStyle = {
                                'min-width': element[0].offsetWidth + 'px',
                                'max-width': element[0].offsetWidth + 'px'
                            };

                            scope.isStyleSet = true;
                        }

                        scope.opened = !scope.opened;
                    };

                    scope.optionChanged = function(selectedOption) {
                        if (angular.isDefined(selectedOption.is_active) && selectedOption.is_active === false) {
                            return;
                        }

                        scope.ngModel = selectedOption;

                        if (angular.isDefined(attr.ngChange)) {
                            scope.ngChange()(selectedOption);
                        }

                        if (angular.isDefined(attr.updateParentRow)) {
                            scope.updateParentRow()(scope.parentRow);
                        }
                    };

                    if (angular.isDefined(attr.appendToBody)) {
                        element.html($templateCache.get('uicore/select/views/select.html'));
                    } else {
                        element.html($templateCache.get(
                            'uicore/select/views/select.html').replace('dropdown-append-to-body', ''));
                    }

                    $compile(element.contents())(scope);

                }
            };
        }]);