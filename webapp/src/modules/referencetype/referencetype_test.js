describe('bricata ui reference type', function() {

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

    describe('CreateReferenceTypeController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;
            controller = $controller('CreateReferenceTypeController', { $scope: $scope});

            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.reference.types.json') > 0 || url.indexOf('reference_types') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.reference.types.json')
            );
        });

        it('check controller initialization', function () {
            expect($scope.states).not.toBeUndefined();
            expect($scope.formData.data).not.toBeUndefined();
            expect($scope.formData.validation).not.toBeUndefined();
        });

        it('check validations', function () {
            expect($scope.formData.validation.name).toBeFalsy();
            expect($scope.formData.validation.urlPrefix).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceNameValidation'});
            expect($scope.formData.validation.name).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceUrlValidation'});
            expect($scope.formData.validation.urlPrefix).toBeTruthy();
        });

        it('check reference type info can be processed for editing', function () {
            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                url_prefix: 'http'
            });

            $scope.processEditReferenceTypeAction();
            expect($scope.states.isEditMode).toBeTruthy();
            expect($scope.formData.data.id).toBe(1);
            expect($scope.formData.data.name).toBe('edit');
            expect($scope.formData.data.url_prefix).toBe('http');
        });

        it('check reference type editing', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceUrlValidation'});

            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                url_prefix: 'http'
            });

            $scope.processEditReferenceTypeAction();

            $httpBackend.expectPUT(function(url) {
                return url.indexOf('signature.reference.types.json') > 0 || url.indexOf('reference_types') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'edit';
            }).respond(
                {}
            );

            $scope.submitReferenceType();
            $httpBackend.flush();
        });

        it('check reference type creation', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'referenceUrlValidation'});

            $scope.formData.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signature.reference.types.json') > 0 || url.indexOf('reference_types') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.submitReferenceType();
            $httpBackend.flush();
        });
    });

    describe('ReferenceInputController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;
            controller = $controller('ReferenceInputController', { $scope: $scope});

            $scope.addNewSignatureModel = {
                data: {
                    references: []
                }
            };
        });

        it('check ReferenceInputController methods', function () {
            expect($scope.addNewSignatureModel.data.references.length).toBe(0);

            $scope.addTypeValueRow();
            expect($scope.addNewSignatureModel.data.references.length).toBe(1);

            $scope.removeTypeValueRow(0);
            expect($scope.addNewSignatureModel.data.references.length).toBe(0);
        });
    });
});