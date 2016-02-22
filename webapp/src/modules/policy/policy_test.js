describe('bricata ui policy', function() {

    var $compile,
        $controller,
        $rootScope,
        $httpBackend,
        ConfigurationService,
        CommonModalService,
        CommonNavigationService,
        GridActionsHelper;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function(_$compile_, _$controller_, _$rootScope_, _$httpBackend_, _ConfigurationService_,
        _CommonModalService_, _CommonNavigationService_, _GridActionsHelper_){
        $compile = _$compile_;
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;

        jasmine.getJSONFixtures().fixturesPath = 'base/src';

        $httpBackend.whenGET(function(url) {
            return url.indexOf("config/app_conf.json") === 0;
        }).respond(
            getJSONFixture('config/app_conf.json')
        );

        ConfigurationService = _ConfigurationService_;
        CommonModalService = _CommonModalService_;
        CommonNavigationService = _CommonNavigationService_;
        GridActionsHelper = _GridActionsHelper_;

        ConfigurationService.loadConfiguration().then(function(data) {
            ConfigurationService.setConfiguration(data);
        });

        $httpBackend.flush();
        $rootScope.$digest();
    }));

    describe('CreatePolicyController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;
            controller = $controller('CreatePolicyController', { $scope: $scope });

            $httpBackend.whenGET(function(url) {
                return url.indexOf('policies.json') > 0 || url.indexOf('policies/lite') > 0;
            }).respond(
                getJSONFixture('json-mocks/policies.json')
            );

            $httpBackend.whenPOST(function(url) {
                return url.indexOf('policies.json') > 0 || url.indexOf('policies') > 0;
            }).respond(
                getJSONFixture('json-mocks/policies.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('policy.detail.signatures.json') > 0 || url.indexOf('policies/1') > 0;
            }).respond(
                {
                    objects:[{id:1}, {id:2}, {id:3}]
                }
            );
        });

        it('check validation without signatures', function () {
            $scope.checkValidationResult();
            expect($scope.formData.isValid).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyNameValidation'});
            expect($scope.formData.isValid).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyDescriptionValidation'});
            expect($scope.formData.isValid).toBeFalsy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyCategoryValidation'});
            expect($scope.formData.isValid).toBeTruthy();
        });

        it('check validation with signatures', function () {
            $scope.checkValidationResult();
            expect($scope.formData.isValid).toBeFalsy();

            $scope._policyType = ConfigurationService.getPolicyTypes()[0];
            $scope.confirmTypeChange();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyDescriptionValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyCategoryValidation'});
            expect($scope.formData.isValid).toBeFalsy();

            $scope.$emit('signature.select.validation.processed', {isValid: true});
            expect($scope.formData.isValid).toBeTruthy();
        });

        it('check policy preview before create', function () {
            spyOn(CommonModalService, 'show');

            $scope._policyType = ConfigurationService.getPolicyTypes()[0];
            $scope.confirmTypeChange();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyDescriptionValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyCategoryValidation'});
            $scope.$emit('signature.select.validation.processed', {isValid: true});
            $scope.previewBeforeSavingCheckboxModel.checked = true;

            $scope.submitPolicy();

            expect(CommonModalService.show).toHaveBeenCalled();
        });

        it('check policy creation', function () {
            spyOn(CommonNavigationService, 'navigateToPoliciesGridPage');

            $scope._policyType = ConfigurationService.getPolicyTypes()[0];
            $scope.confirmTypeChange();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyNameValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyDescriptionValidation'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'policyCategoryValidation'});
            $scope.$emit('signature.select.validation.processed', {isValid: true});

            $scope.submitPolicy();
            $httpBackend.flush();
            expect(CommonNavigationService.navigateToPoliciesGridPage).toHaveBeenCalled();
        });

        it('check policy type changes', function () {
            $scope._policyType = ConfigurationService.getPolicyTypes()[0];
            $scope.updatePolicyType();

            expect($scope._policyType.signatureSelect).toBe($scope.policyData.type.signatureSelect);
        });

        it('check policy type change cancelled', function () {
            spyOn(CommonModalService, 'show');
            var firstType = ConfigurationService.getPolicyTypes()[0];
            $scope._policyType = firstType;
            $scope.updatePolicyType();

            $scope.policyData.selectedSignatures = [{}];
            $scope._policyType = ConfigurationService.getPolicyTypes()[1];
            $scope.updatePolicyType();
            expect(CommonModalService.show).toHaveBeenCalled();

            $scope.declineTypeChange();
            expect($scope._policyType.signatureSelect).toBe(firstType.signatureSelect);
        });

        it('check policy info can be processed for cloning', function () {
            GridActionsHelper.storeGridCloneData({
                id: 1,
                name: 'clone',
                description: 'clone test',
                policy_type: ConfigurationService.getPolicyTypes()[0].value
            });

            $scope.processClonePolicyAction();
            $httpBackend.flush();

            expect($scope.policyData.id).toBe(-1);
            expect($scope.policyData.policyName).toBe('createPolicy.clonePolicyPrefixAndName');
            expect($scope.policyData.description).toBe('clone test');
            expect($scope.preselectedData.length).toBe(3);
        });

        it('check policy info can be processed for editing', function () {
            GridActionsHelper.storeGridEditData({
                id: 1,
                name: 'edit',
                description: 'edit test',
                policy_type: ConfigurationService.getPolicyTypes()[0].value
            });

            $scope.processEditPolicyAction();
            $httpBackend.flush();

            expect($scope.policyData.id).toBe(1);
            expect($scope.policyData.policyName).toBe('edit');
            expect($scope.policyData.description).toBe('edit test');
            expect($scope.preselectedData.length).toBe(3);
        });
    });

    describe('PolicySignaturesPreviewController methods check', function () {
        var $scope, controller;
        var isModalClosed = false;
        var submitCalled = false;

        beforeEach(function () {
            $httpBackend.whenPOST(function(url) {
                return url.indexOf('preview.json') > 0 || url.indexOf('policies') > 0;
            }).respond(
                getJSONFixture('json-mocks/policies.json_preview.json?')
            );

            $scope = $rootScope;
            var fakeModal = {
                opened: {
                    then: function(){}
                },
                dismiss: function(){
                    isModalClosed = true;
                }
            };

            controller = $controller('PolicySignaturesPreviewController', {
                $scope: $scope,
                $modalInstance: fakeModal,
                policyData: {id: 1},
                submitCallback: function(){
                    submitCalled = true;
                },
                submitBtnLbl: ''
            });
            $httpBackend.flush();
        });

        it('check controller initialization', function () {
            expect($scope.rules).not.toBeUndefined();
            expect($scope.pagination.totalItemsCount).not.toBeUndefined();
            expect($scope.displayedRules).not.toBeUndefined();
            expect($scope.isRulesLoading).toBeFalsy();
        });

        it('check modal can be closed', function () {
            expect(isModalClosed).toBeFalsy();
            $scope.cancelModal();
            expect(isModalClosed).toBeTruthy();
        });

        it('check injected submit handler can be invoked', function () {
            expect(submitCalled).toBeFalsy();
            $scope.submitModal();
            expect(submitCalled).toBeTruthy();
        });
    });
});