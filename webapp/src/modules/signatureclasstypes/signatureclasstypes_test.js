describe('bricata ui signature class type', function() {

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

    describe('CreateSignatureClassTypeController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;

            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.class.types.item.json') > 0 ||
                    url.indexOf('signature_class_types') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.class.types.item.json')
            );

            controller = $controller('CreateSignatureClassTypeController', { $scope: $scope, gridStandardActions: []});
        });

        it('check controller initialization', function () {
            expect($scope.formData.data).not.toBeUndefined();
            expect($scope.formData.validation).not.toBeUndefined();
            expect($scope.states).not.toBeUndefined();
        });

        it('check validations', function () {
            spyOn($scope, 'createEditSignatureClassType');
            expect($scope.formData.validation.name).toBeFalsy();
            expect($scope.formData.validation.shortName).toBeFalsy();
            expect($scope.formData.validation.priority).toBeFalsy();
            $scope.submitSignatureClassType();
            expect($scope.createEditSignatureClassType).not.toHaveBeenCalled();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureClassTypeNameValidation'});
            expect($scope.formData.validation.name).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypeShortNameValidation'});
            expect($scope.formData.validation.shortName).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypePriorityValidation'});
            expect($scope.formData.validation.priority).toBeTruthy();
        });

        it('check signature class type info can be processed for editing', function () {
            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                short_name: 'short',
                priority: 123
            });

            $scope.processEditSignatureClassTypeAction();
            expect($scope.states.isEditMode).toBeTruthy();
            expect($scope.formData.data.id).toBe(1);
            expect($scope.formData.data.name).toBe('edit');
            expect($scope.formData.data.short_name).toBe('short');
            expect($scope.formData.data.priority).toBe(123);
        });

        it('check signature class type editing', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureClassTypeNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypeShortNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypePriorityValidation'});

            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                short_name: 'short',
                priority: 123
            });

            $scope.processEditSignatureClassTypeAction();

            $httpBackend.expectPUT(function(url) {
                return url.indexOf('signature.class.types.item.json') > 0 || url.indexOf('signature_class_types') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'edit' && JSON.parse(dataStr).short_name == 'short';
            }).respond(
                {}
            );

            $scope.submitSignatureClassType();
            $httpBackend.flush();
        });

        it('check signature class type creation', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureClassTypeNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypeShortNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name:
                'signatureClassTypePriorityValidation'});

            $scope.formData.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signature.class.types.item.json') > 0 || url.indexOf('signature_class_types') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.submitSignatureClassType();
            $httpBackend.flush();
        });

    });
});