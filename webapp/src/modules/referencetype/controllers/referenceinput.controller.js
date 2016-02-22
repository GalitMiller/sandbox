angular.module('bricata.ui.referencetype')
    .controller('ReferenceInputController', ['$scope', function($scope) {

        $scope.addTypeValueRow = function () {
            $scope.addNewSignatureModel.data.references.push({typeId: null, value: ''});

            $scope.$emit('content.changed');
            $scope.$emit('scrollable.scroll.bottom');

        };

        $scope.removeTypeValueRow = function (index) {
            $scope.addNewSignatureModel.data.references.splice(index, 1);
            $scope.$emit('content.changed');
        };

    }]);
