describe('bricata ui signature category', function() {

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

    describe('CreateSignatureCategoryController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;

            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signatures.categories.lite.json') > 0 ||
                    url.indexOf('signature_categories/lite') > 0;
            }).respond(
                getJSONFixture('json-mocks/signatures.categories.lite.json')
            );

            controller = $controller('CreateSignatureCategoryController', { $scope: $scope, gridStandardActions: [] });
        });

        it('check controller initialization', function () {
            expect($scope.formData.data).not.toBeUndefined();
            expect($scope.formData.validation).not.toBeUndefined();
            expect($scope.states).not.toBeUndefined();
        });

        it('check validations', function () {
            spyOn($scope, 'createEditSignatureCategory');
            expect($scope.formData.validation.name).toBeFalsy();
            expect($scope.formData.validation.description).toBeFalsy();
            $scope.submitSignatureCategory();
            expect($scope.createEditSignatureCategory).not.toHaveBeenCalled();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureCategoryNameValidation'});
            expect($scope.formData.validation.name).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true,
                name: 'signatureCategoryDescriptionValidation'});
            expect($scope.formData.validation.description).toBeTruthy();
        });

        it('check signature category info can be processed for editing', function () {
            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                description: 'test'
            });

            $scope.processEditSignatureCategoryAction();
            expect($scope.states.isEditMode).toBeTruthy();
            expect($scope.formData.data.id).toBe(1);
            expect($scope.formData.data.name).toBe('edit');
            expect($scope.formData.data.description).toBe('test');
        });

        it('check signature category editing', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureCategoryNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true,
                name: 'signatureCategoryDescriptionValidation'});

            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                description: 'test'
            });

            $scope.processEditSignatureCategoryAction();

            $httpBackend.expectPUT(function(url) {
                return url.indexOf('signatures.categories.item.json') > 0 || url.indexOf('signature_categories') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'edit' && JSON.parse(dataStr).description == 'test';
            }).respond(
                {}
            );

            $scope.submitSignatureCategory();
            $httpBackend.flush();
        });

        it('check signature category creation', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureCategoryNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true,
                name: 'signatureCategoryDescriptionValidation'});

            $scope.formData.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signatures.categories.item.json') > 0 || url.indexOf('signature_categories') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.submitSignatureCategory();
            $httpBackend.flush();
        });

    });
});