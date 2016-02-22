angular.module("bricata.ui.referencetype")
    .directive("referenceInput", [function () {
        return {
            restrict: 'E',
            templateUrl: 'modules/referencetype/views/referenceinput.html',
            controller: 'ReferenceInputController'
        };
    }]);