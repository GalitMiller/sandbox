describe('bricata ui sensor', function() {

    var $compile,
        $controller,
        $rootScope,
        $httpBackend;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function (_$compile_, _$controller_, _$rootScope_, _$httpBackend_) {
        $compile = _$compile_;
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;

        $rootScope.$digest();
    }));

    describe('ActivateSensorController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;

            var fakeModal = {
                opened: {
                    then: function(){}
                },
                close: function(){}
            };

            controller = $controller('ActivateSensorController', { $scope: $scope, $modalInstance: fakeModal,
                inactiveSensor: {name: 'test', id: 1, hostname: 'test.com'} });
        });

        it('check controller initialization', function () {
            expect($scope.formData.activationData).not.toBeUndefined();
            expect($scope.formData.validation).not.toBeUndefined();
            expect($scope.currentSensorName).toBe('test');
        });

        it('check validations', function () {
            expect($scope.formData.validation.host).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: false, name: 'sensorHostValidation'});
            expect($scope.formData.validation.host).toBeFalsy();
            expect($scope.formData.isValid).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'sensorHostValidation'});
            expect($scope.formData.validation.host).toBeTruthy();
            expect($scope.formData.isValid).toBeTruthy();
        });

        it('check sensor activation', function () {
            $httpBackend.expectPOST(function(url) {
                return url.indexOf('sensor.activated.json') > 0 || url.indexOf('take_control') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).sensorId == 1 && JSON.parse(dataStr).hostname == 'test.com';
            }).respond(
                {}
            );

            $scope.handleKeyPress({which: 13});
            $httpBackend.flush();
        });

    });
});