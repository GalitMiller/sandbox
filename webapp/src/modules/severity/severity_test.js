describe('bricata ui severity', function() {

    var $compile,
        $controller,
        $rootScope,
        $httpBackend,
        GridActionsHelper;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function (_$compile_, _$controller_, _$rootScope_, _$httpBackend_, _GridActionsHelper_) {
        $compile = _$compile_;
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;
        GridActionsHelper = _GridActionsHelper_;

        $rootScope.$digest();
    }));

    describe('CreateSeverityController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;

            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.severities.json')
            );

            controller = $controller('CreateSeverityController', { $scope: $scope, gridStandardActions: [] });
        });

        it('check controller initialization', function () {
            expect($scope.formData.data).not.toBeUndefined();
            expect($scope.formData.validation).not.toBeUndefined();
            expect($scope.states).not.toBeUndefined();
        });

        it('check validations', function () {
            spyOn($scope, 'createEditSeverity');
            expect($scope.formData.validation.name).toBeFalsy();
            expect($scope.formData.validation.priority).toBeFalsy();
            expect($scope.formData.validation.bgClr).toBeTruthy();
            expect($scope.formData.validation.txtClr).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityName'});
            expect($scope.formData.validation.name).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityPriority'});
            expect($scope.formData.validation.priority).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: false, name: 'signatureSeverityBgColor'});
            expect($scope.formData.validation.bgClr).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: false, name: 'signatureSeverityTxtColor'});
            expect($scope.formData.validation.txtClr).toBeFalsy();

            $scope.submitSeverity();
            expect($scope.createEditSeverity).not.toHaveBeenCalled();
        });

        it('check severity info can be processed for editing', function () {
            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                weight: 123,
                bg_color: '#fff',
                text_color: '#000'
            });

            $scope.processEditSeverityAction();
            expect($scope.states.isEditMode).toBeTruthy();
            expect($scope.formData.data.id).toBe(1);
            expect($scope.formData.data.name).toBe('edit');
            expect($scope.formData.data.weight).toBe(123);
            expect($scope.formData.data.bg_color).toBe('#fff');
            expect($scope.formData.data.text_color).toBe('#000');
        });

        it('check severity editing', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityName'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityPriority'});

            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                weight: 123,
                bg_color: '#fff',
                text_color: '#000'
            });

            $scope.processEditSeverityAction();

            $httpBackend.expectPUT(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'edit';
            }).respond(
                {}
            );

            $scope.createEditSeverity();
            $httpBackend.flush();
        });

        it('check severity creation', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityName'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityPriority'});

            $scope.formData.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.createEditSeverity();
            $httpBackend.flush();
        });

    });
});