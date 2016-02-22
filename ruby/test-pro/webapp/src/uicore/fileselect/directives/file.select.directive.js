angular.module("bricata.uicore.fileselect")
    .directive("fileSelect", [
    function () {
        return {
            restrict: 'E',
            templateUrl: 'uicore/fileselect/views/file-select.html',
            link: function($scope, $element) {
                var button, fileField, proxy;
                fileField = angular.element($element[0].querySelector('[type="file"]')).on('change', function() {
                    proxy.val(angular.element(this).val()
                        .replace(/C:\\fakepath\\/i, '').replace(/\\/g, '/').replace(/.*\//, ''));

                    $scope.$emit('file.selected', fileField[0].files[0]);
                });
                proxy = angular.element($element[0].querySelector('[type="text"]')).on('click', function() {
                    fileField.triggerHandler('click');
                }).on('keypress keydown keyup', function(event){
                    event.preventDefault();
                });
                button = angular.element($element[0].querySelector('[type="button"]')).on('click', function() {
                    fileField.triggerHandler('click');
                });
            }
        };
    }]);