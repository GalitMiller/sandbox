describe('bricata ui signature', function() {

    var $rootScope,
        $httpBackend,
        $controller,
        SignatureSelectionService,
        SignatureWizardService,
        SignatureDataService,
        ConfigurationService,
        CommonModalService,
        SignatureImportHelperService,
        CommonErrorMessageService,
        CommonAlertMessageService,
        SignatureCategoriesModel,
        GridActionsHelper;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function(_$rootScope_, _$httpBackend_, _$controller_,  _SignatureSelectionService_,
                               _SignatureWizardService_, _SignatureDataService_, _ConfigurationService_,
                               _CommonModalService_, _SignatureImportHelperService_, _CommonErrorMessageService_,
                               _CommonAlertMessageService_, _SignatureCategoriesModel_, _GridActionsHelper_){
        $rootScope = _$rootScope_.$new();
        $httpBackend = _$httpBackend_;
        $controller = _$controller_;

        SignatureSelectionService = _SignatureSelectionService_;
        SignatureWizardService = _SignatureWizardService_;
        SignatureDataService = _SignatureDataService_;
        ConfigurationService = _ConfigurationService_;
        CommonModalService = _CommonModalService_;
        SignatureImportHelperService = _SignatureImportHelperService_;
        CommonErrorMessageService = _CommonErrorMessageService_;
        CommonAlertMessageService = _CommonAlertMessageService_;
        SignatureCategoriesModel = _SignatureCategoriesModel_;
        GridActionsHelper = _GridActionsHelper_;

        $rootScope.$digest();
    }));

    describe('SignatureSelectionService methods', function() {
        it('check sorting by id', function() {
            var dataRows = [
                {id: 2},
                {id: 1},
                {id: 4},
                {id: 5},
                {id: 3}
            ];

            SignatureSelectionService.sortById(dataRows);
            expect(dataRows.length).toBe(5);
            expect(dataRows[0].id).toBe(1);
            expect(dataRows[1].id).toBe(2);
            expect(dataRows[2].id).toBe(3);
            expect(dataRows[3].id).toBe(4);
            expect(dataRows[4].id).toBe(5);
        });

        it('check selected extraction', function() {
            var selectionInfoObj = {
                1: true,
                2: false,
                3: true,
                4: false,
                5: true
            };

            var selectedIds = SignatureSelectionService.extractSelectedIds(selectionInfoObj);
            expect(selectedIds.length).toBe(3);
            expect(selectedIds[0]).toBe('1');
            expect(selectedIds[1]).toBe('3');
            expect(selectedIds[2]).toBe('5');

            selectedIds = SignatureSelectionService.extractSelectedIds({});
            expect(selectedIds.length).toBe(0);
        });

        it('check category selection processing', function() {
            var selectedCategoryIDs = {
                1: true,
                2: false,
                3: true,
                4: false,
                5: true
            };

            var signatureCategories = [
                {id: 1, signatures: [{id: 11}, {id: 12}, {id: 13}]},
                {id: 2, signatures: [{id: 21}, {id: 22}, {id: 23}]},
                {id: 3, signatures: [{id: 31}, {id: 32}, {id: 33}]},
                {id: 4, signatures: [{id: 41}, {id: 42}, {id: 43}]},
                {id: 5, signatures: [{id: 51}, {id: 52}, {id: 53}]}
            ];

            var recipientModel = [{id: 'x'}, {id: 'y'}, {id: 'z'}];

            SignatureSelectionService.processCategorySelectionChange(selectedCategoryIDs, signatureCategories,
                recipientModel);

            expect(recipientModel.length).toBe(9);
            expect(recipientModel[0].id).toBe(11);
            expect(recipientModel[1].id).toBe(12);
            expect(recipientModel[2].id).toBe(13);
            expect(recipientModel[3].id).toBe(31);
            expect(recipientModel[4].id).toBe(32);
            expect(recipientModel[5].id).toBe(33);
            expect(recipientModel[6].id).toBe(51);
            expect(recipientModel[7].id).toBe(52);
            expect(recipientModel[8].id).toBe(53);
        });

        it('check signature selection processing', function() {
            var selectedSignatureIDs = {
                1: true,
                2: false,
                3: true,
                4: false,
                5: true
            };

            var availableSignatures = [
                {id: 1},
                {id: 2},
                {id: 3},
                {id: 4},
                {id: 5}
            ];

            var selectionModel = [{id: 4}, {id: 5}];

            SignatureSelectionService.processSignatureSelectionChange(selectedSignatureIDs, availableSignatures,
                selectionModel);

            expect(selectionModel.length).toBe(3);
            expect(selectionModel[0].id).toBe(5);
            expect(selectionModel[1].id).toBe(1);
            expect(selectionModel[2].id).toBe(3);
        });
    });

    describe('SignatureWizardService methods and NewSignatureModalController', function() {
        beforeEach(function() {
            jasmine.getJSONFixtures().fixturesPath = 'base/src';

            //need both url versions here to match Dev and Prod testing
            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.class.types.item.json') > 0 || url.indexOf('signature_class_types') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.class.types.item.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.reference.types.json') > 0 || url.indexOf('reference_types') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.reference.types.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.severities.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.protocols.json') > 0 || url.indexOf('signature_protocols') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.protocols.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('new_sid.json') > 0 || url.indexOf('new_sid') > 0;
            }).respond(
                getJSONFixture('json-mocks/new_sid.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signatures.categories.lite.json') > 0 || url.indexOf('signature_categories') > 0;
            }).respond(
                getJSONFixture('json-mocks/signatures.categories.lite.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signatures.item.json') > 0 || url.indexOf('signatures/1') > 0;
            }).respond(
                getJSONFixture('json-mocks/signatures.item.json')
            );

            $httpBackend.whenPOST(function(url) {
                return url.indexOf('preview.json') > 0 || url.indexOf('signatures/preview') > 0;
            }).respond(
                getJSONFixture('json-mocks/preview.json')
            );

            $httpBackend.whenPOST(function(url) {
                return url.indexOf('signature.new.json') > 0 || url.indexOf('signatures') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.new.json')
            );

            $httpBackend.whenPUT(function(url) {
                return url.indexOf('signatures.item.json') > 0 || url.indexOf('signatures') > 0;
            }).respond(
                getJSONFixture('json-mocks/signatures.item.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf("config/app_conf.json") === 0;
            }).respond(
                getJSONFixture('config/app_conf.json')
            );

            ConfigurationService.loadConfiguration().then(function(data) {
                ConfigurationService.setConfiguration(data);
            });

            $httpBackend.flush();
            $rootScope.$digest();
        });

        it('check initializing of common model', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            expect(signatureModel.data).not.toBe(null);
            expect(signatureModel.data.action).toBe(null);
            expect(signatureModel.data.protocolId).toBe(null);

            expect(signatureModel.data.source.ip.ip).toBe('');
            expect(signatureModel.data.source.ip.anyIp).toBeFalsy();
            expect(signatureModel.data.source.port.port).toBe('');
            expect(signatureModel.data.source.port.anyPort).toBeFalsy();

            expect(signatureModel.data.unidirectional).toBeTruthy();

            expect(signatureModel.data.destination.ip.ip).toBe('');
            expect(signatureModel.data.destination.ip.anyIp).toBeFalsy();
            expect(signatureModel.data.destination.port.port).toBe('');
            expect(signatureModel.data.destination.port.anyPort).toBeFalsy();

            expect(signatureModel.data.name).toBe('');
            expect(signatureModel.data.categoryId).toBe(null);
            expect(signatureModel.data.message).toBe('');
            expect(signatureModel.data.flowControlTxt).toBe('');
            expect(signatureModel.data.contentTxt).toBe('');
            expect(signatureModel.data.classTypeID).toBe(null);
            expect(signatureModel.data.revision).toBe(1);

            expect(signatureModel.data.references.length).toBe(1);
            expect(signatureModel.data.references[0].typeId).toBe(null);
            expect(signatureModel.data.references[0].value).toBe('');
            expect(signatureModel.data.sid).toBe(2015040800);
            expect(signatureModel.data.gid).toBe(1);
            expect(signatureModel.data.severityId).toBe(null);

            expect(signatureModel.values.classTypeList.length).toBe(36);
            expect(signatureModel.values.referenceTypes.length).toBe(19);
            expect(signatureModel.values.severities.length).toBe(4);
            expect(signatureModel.values.protocolList.length).toBe(9);
            expect(signatureModel.categories.length).toBe(3);
        });

        it('check converting edit data to common model', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            SignatureDataService.getSignature(1).then(function success(editData) {
                SignatureWizardService.convertEditDataToModel(editData, signatureModel.data);

                expect(signatureModel.data.action).toBe('pass');
                expect(signatureModel.data.protocolId).toBe(4);
                expect(signatureModel.data.unidirectional).toBeTruthy();

                expect(signatureModel.data.source.ip.anyIp).toBeTruthy();
                expect(signatureModel.data.source.port.anyPort).toBeTruthy();

                expect(signatureModel.data.destination.ip.anyIp).toBeTruthy();
                expect(signatureModel.data.destination.port.anyPort).toBeTruthy();

                expect(signatureModel.data.name).toBe('test new');
                expect(signatureModel.data.categoryId).toBe(1);
                expect(signatureModel.data.message).toBe('sasa');
                expect(signatureModel.data.flowControlTxt).toBe('');
                expect(signatureModel.data.contentTxt).toBe('');

                expect(signatureModel.data.classTypeID).toBe(null);
                expect(signatureModel.data.revision).toBe(1);
                expect(signatureModel.data.references.length).toBe(1);
                expect(signatureModel.data.references[0].typeId).toBe(null);
                expect(signatureModel.data.references[0].value).toBe('');

                expect(signatureModel.data.sid).toBe(2015061501);
                expect(signatureModel.data.gid).toBe(1);
                expect(signatureModel.data.severityId).toBe(1);
            });
            $httpBackend.flush();
        });

        it('check processing validation event', function() {
            var validationModel = {
                first: {
                    isActionValid: false,
                    isProtocolValid: false
                },
                second: {
                    isNameValid: false,
                    isCategoryValid: false
                }
            };

            var eventDataFirst = {
                name: 'first_isActionValid',
                isValid: true
            };
            var eventDataSecond = {
                name: 'second_isCategoryValid',
                isValid: true
            };
            var eventDataFake = {
                name: 'fake_fake',
                isValid: true
            };


            SignatureWizardService.processValidationResults(validationModel, undefined);
            expect(validationModel.first.isActionValid).toBeFalsy();
            expect(validationModel.first.isProtocolValid).toBeFalsy();
            expect(validationModel.second.isNameValid).toBeFalsy();
            expect(validationModel.second.isCategoryValid).toBeFalsy();

            SignatureWizardService.processValidationResults(validationModel, {});
            expect(validationModel.first.isActionValid).toBeFalsy();
            expect(validationModel.first.isProtocolValid).toBeFalsy();
            expect(validationModel.second.isNameValid).toBeFalsy();
            expect(validationModel.second.isCategoryValid).toBeFalsy();

            SignatureWizardService.processValidationResults(validationModel, {name: 'fake'});
            expect(validationModel.first.isActionValid).toBeFalsy();
            expect(validationModel.first.isProtocolValid).toBeFalsy();
            expect(validationModel.second.isNameValid).toBeFalsy();
            expect(validationModel.second.isCategoryValid).toBeFalsy();

            SignatureWizardService.processValidationResults(validationModel, eventDataFirst);
            SignatureWizardService.processValidationResults(validationModel, eventDataSecond);
            SignatureWizardService.processValidationResults(validationModel, eventDataFake);
            expect(validationModel.first.isActionValid).toBeTruthy();
            expect(validationModel.first.isProtocolValid).toBeFalsy();
            expect(validationModel.second.isNameValid).toBeFalsy();
            expect(validationModel.second.isCategoryValid).toBeTruthy();
        });

        it('check processing validation for steps', function() {
            var validationModel = {
                first: {
                    isActionValid: true,
                    isProtocolValid: true,
                    isSourceValid: true,
                    isDestinationValid: true
                },
                second: {
                    isNameValid: false,
                    isCategoryValid: false,
                    isMessageValid: false
                },
                third: {
                    isClassTypeValid: false,
                    isReferenceValid: true,
                    noDuplicatedReferenceFound: true,
                    isRevisionValid: false,
                    isSIDValid: false,
                    isGIDValid: false
                }
            };

            expect(SignatureWizardService.isStepValid(validationModel.first)).toBeTruthy();
            expect(SignatureWizardService.isStepValid(validationModel.second)).toBeFalsy();
            expect(SignatureWizardService.isStepValid(validationModel.third)).toBeFalsy();
        });

        it('check sync severity with selected class type', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            SignatureWizardService.syncSeverityWithClassTypeSelection(signatureModel.data, signatureModel.values);
            expect(signatureModel.data.severityId).toBe(null);

            signatureModel.data.classTypeID = 1;
            SignatureWizardService.syncSeverityWithClassTypeSelection(signatureModel.data, signatureModel.values);
            expect(signatureModel.data.severityId).toBe(3);

            signatureModel.data.classTypeID = 35;
            SignatureWizardService.syncSeverityWithClassTypeSelection(signatureModel.data, signatureModel.values);
            expect(signatureModel.data.severityId).toBe(3);

            signatureModel.data.classTypeID = 3;
            SignatureWizardService.syncSeverityWithClassTypeSelection(signatureModel.data, signatureModel.values);
            expect(signatureModel.data.severityId).toBe(2);

            signatureModel.data.classTypeID = 10;
            SignatureWizardService.syncSeverityWithClassTypeSelection(signatureModel.data, signatureModel.values);
            expect(signatureModel.data.severityId).toBe(1);
        });

        it('check preview signature modal is triggered to be open', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            spyOn(CommonModalService, 'show');
            SignatureWizardService.previewSignature(signatureModel.data);
            $httpBackend.flush();
            expect(CommonModalService.show).toHaveBeenCalled();
        });

        it('check new signature category modal is triggered to be open', function() {
            spyOn(CommonModalService, 'show');
            SignatureWizardService.openNewSignatureCategoryDialog();
            expect(CommonModalService.show).toHaveBeenCalled();
        });

        it('check new signature severity modal is triggered to be open', function() {
            spyOn(CommonModalService, 'show');
            SignatureWizardService.openNewSignatureSeverityDialog();
            expect(CommonModalService.show).toHaveBeenCalled();
        });

        it('check save signature call', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            var isSignatureSaved = false;
            var successHandler = function(data){
                isSignatureSaved = true;
            };
            SignatureWizardService.saveSignature(signatureModel.data, successHandler);
            $httpBackend.flush();

            expect(isSignatureSaved).toBeTruthy();
        });

        it('check edit signature call', function() {
            var signatureModel = SignatureWizardService.initializeModel();
            $httpBackend.flush();

            var isSignatureEdited = false;
            var successHandler = function(data){
                isSignatureEdited = true;
            };
            SignatureWizardService.editSignature(signatureModel.data, successHandler);
            $httpBackend.flush();

            expect(isSignatureEdited).toBeTruthy();
        });

        describe('NewSignatureModalController methods check', function () {
            var $scope, controller;

            beforeEach(function () {
                $scope = $rootScope;

                var fakeModal = {
                    opened: {
                        then: function () {
                        }
                    },
                    close: function () {
                    },
                    dismiss: function () {
                    }
                };

                controller = $controller('NewSignatureModalController', { $scope: $scope, $modalInstance: fakeModal,
                    categoryId: 1});
                $httpBackend.flush();
            });

            it('check controller initialization', function () {
                expect($scope.states).not.toBeUndefined();
                expect($scope.allowedSteps).not.toBeUndefined();
                expect($scope.currentStep).not.toBeUndefined();
                expect($scope.addNewSignatureModel).not.toBeUndefined();
            });

            it('check navigation', function () {
                $scope.addNewSignatureModel.goToRulesInformation();
                expect($scope.currentStep.first).toBeTruthy();
                expect($scope.currentStep.second).toBeFalsy();
                expect($scope.currentStep.third).toBeFalsy();

                //we remain on the first step
                $scope.addNewSignatureModel.goToSignatureInformation();
                expect($scope.currentStep.first).toBeTruthy();
                expect($scope.currentStep.second).toBeFalsy();
                expect($scope.currentStep.third).toBeFalsy();

                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: false },
                    third: { fake: false }
                };

                //can navigate to second step
                $scope.addNewSignatureModel.goToSignatureInformation();
                expect($scope.currentStep.first).toBeFalsy();
                expect($scope.currentStep.second).toBeTruthy();
                expect($scope.currentStep.third).toBeFalsy();

                //remains on the second step
                $scope.addNewSignatureModel.goToMetaInformation();
                expect($scope.currentStep.first).toBeFalsy();
                expect($scope.currentStep.second).toBeTruthy();
                expect($scope.currentStep.third).toBeFalsy();

                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: false }
                };

                //can navigate to the third step
                $scope.addNewSignatureModel.goToMetaInformation();
                expect($scope.currentStep.first).toBeFalsy();
                expect($scope.currentStep.second).toBeFalsy();
                expect($scope.currentStep.third).toBeTruthy();

                //final step isn't allowed
                spyOn($scope, 'saveAndClose');
                $scope.createSignature();
                expect($scope.saveAndClose).not.toHaveBeenCalled();
            });

            it('check new signature severity modal opens and closes', function() {
                expect($scope.states.isSubModalShown).toBeFalsy();

                spyOn(CommonModalService, 'show');
                $scope.openNewSeverityModal();
                expect(CommonModalService.show).toHaveBeenCalled();
                expect($scope.states.isSubModalShown).toBeTruthy();

                $scope.newSeverityCreated({});
                expect($scope.states.isSubModalShown).toBeFalsy();
            });

            it('check new signature category modal opens and closes', function() {
                expect($scope.states.isSubModalShown).toBeFalsy();

                spyOn(CommonModalService, 'show');
                $scope.openNewCategoryModal();
                expect(CommonModalService.show).toHaveBeenCalled();
                expect($scope.states.isSubModalShown).toBeTruthy();

                $scope.newCategoryCreated({});
                expect($scope.states.isSubModalShown).toBeFalsy();
            });

            it('check preview dialog shown and submitted without error', function() {
                spyOn($scope, 'saveAndClose');
                spyOn(CommonModalService, 'show');

                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: true }
                };

                $scope.addNewSignatureModel.previewSignaturesBeforeSavingCheckBox.checked = true;
                $scope.createSignature();
                $httpBackend.flush();

                //preview dialog is shown instead of final submit
                expect(CommonModalService.show).toHaveBeenCalled();
                expect($scope.states.isSubModalShown).toBeTruthy();

                expect($scope.saveAndClose).not.toHaveBeenCalled();
            });

            it('check creation', function() {
                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: true }
                };

                $scope.addNewSignatureModel.data.name = 'new';

                $httpBackend.expectPOST(function(url) {
                    return url.indexOf('signature.new.json') > 0 || url.indexOf('signatures') > 0;
                }, function(dataStr) {
                    return JSON.parse(dataStr).name == 'new';
                }).respond(
                    getJSONFixture('json-mocks/signature.new.json')
                );

                $scope.createSignature();
                $httpBackend.flush();
            });
        });

        describe('SignatureWizardController methods check', function () {
            var $scope, controller;

            beforeEach(function () {
                $scope = $rootScope;

                controller = $controller('SignatureWizardController', { $scope: $scope, gridStandardActions: []});
                $httpBackend.flush();
            });

            it('check controller initialization', function () {
                expect($scope.labels).not.toBeUndefined();
                expect($scope.helpLinks).not.toBeUndefined();
                expect($scope.isDataValid).toBeFalsy();
                expect($scope.isEditMode).toBeFalsy();
                expect($scope.addNewSignatureModel).not.toBeUndefined();
            });

            it('check validation', function () {
                $scope.addNewSignatureModel.validation = {
                    first: { fake: false },
                    second: { fake: false },
                    third: { isReferenceValid: false }
                };

                $scope.processValidationResult();
                expect($scope.isDataValid).toBeFalsy();

                $scope.$emit('ip.input.validation.processed', {isValid: true, name: 'first_fake'});
                $scope.$emit('input.text.validation.processed', {isValid: true, name: 'second_fake'});
                $scope.$emit('reference.input.validation.processed', {isValid: true});

                expect($scope.isDataValid).toBeTruthy();
            });

            it('check new signature severity modal opens and closes', function() {
                spyOn(CommonModalService, 'show');
                $scope.openNewSeverityModal();
                expect(CommonModalService.show).toHaveBeenCalled();

                $scope.newSeverityCreated({});
            });

            it('check new signature category modal opens and closes', function() {
                spyOn(CommonModalService, 'show');
                $scope.openNewCategoryModal();
                expect(CommonModalService.show).toHaveBeenCalled();

                $scope.newCategoryCreated({});
            });

            it('check preview dialog shown', function() {
                spyOn($scope, 'saveAndClose');
                spyOn(CommonModalService, 'show');

                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: true }
                };

                $scope.addNewSignatureModel.previewSignaturesBeforeSavingCheckBox.checked = true;
                $scope.createSignature();
                $httpBackend.flush();

                //preview dialog is shown instead of final submit
                expect(CommonModalService.show).toHaveBeenCalled();
                expect($scope.saveAndClose).not.toHaveBeenCalled();
            });

            it('check signature editing', function () {
                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: true }
                };

                GridActionsHelper.storeGridEditData({
                    id: 1
                });

                $scope.processEditSignatureAction();
                $httpBackend.flush();

                expect($scope.isEditMode).toBeTruthy();
                var editedName = $scope.addNewSignatureModel.data.name;
                expect(editedName).not.toBe('');

                $httpBackend.expectPUT(function(url) {
                    return url.indexOf('signatures.item.json') > 0 || url.indexOf('signatures') > 0;
                }, function(dataStr) {
                    return JSON.parse(dataStr).name == editedName;
                }).respond(
                    {}
                );

                $scope.createSignature();
                $httpBackend.flush();
            });

            it('check signature cloning', function () {
                $scope.addNewSignatureModel.validation = {
                    first: { fake: true },
                    second: { fake: true },
                    third: { fake: true }
                };

                GridActionsHelper.storeGridCloneData({
                    id: 1
                });

                $scope.processCloneSignatureAction();
                $httpBackend.flush();

                expect($scope.isEditMode).toBeFalsy();
                var clonedName = $scope.addNewSignatureModel.data.name;
                expect(clonedName).not.toBe('');

                $httpBackend.expectPOST(function(url) {
                    return url.indexOf('signatures.item.json') > 0 || url.indexOf('signatures') > 0;
                }, function(dataStr) {
                    return JSON.parse(dataStr).name == clonedName;
                }).respond(
                    {}
                );

                $scope.createSignature();
                $httpBackend.flush();
            });
        });

    });

    describe('SignatureImportHelperService methods', function() {
        it('check rules validation fails on empty name', function() {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            var rules = [
                {is_valid: false, name: 'invalid_rule'},
                {is_valid: true, name: 'rule_1'},
                {is_valid: true, name: ''}
            ];

            var validationResult = SignatureImportHelperService.validateRules(rules, true);
            expect(validationResult.result).toBeFalsy();
            expect(validationResult.pRuleId).toBe('2');
            expect(CommonErrorMessageService.showErrorMessage).toHaveBeenCalled();
        });

        it('check rules validation fails on duplicated name', function() {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            var rules = [
                {is_valid: false, name: 'invalid_rule'},
                {is_valid: true, name: 'rule_1'},
                {is_valid: true, name: 'rule_2'},
                {is_valid: true, name: 'rule_1'}
            ];

            var validationResult = SignatureImportHelperService.validateRules(rules, true);
            expect(validationResult.result).toBeFalsy();
            expect(validationResult.pRuleId).toBe('3');
            expect(CommonErrorMessageService.showErrorMessage).toHaveBeenCalled();
        });

        it('check rules validation fails if nothing selected', function() {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            var rules = [
                {is_valid: false, name: 'invalid_rule'},
                {is_valid: true, name: 'rule_1'},
                {is_valid: true, name: 'rule_2'},
                {is_valid: true, name: 'rule_3'}
            ];

            var validationResult = SignatureImportHelperService.validateRules(rules, false);
            expect(validationResult.result).toBeFalsy();
            expect(validationResult.pRuleId).toBe('');
            expect(CommonErrorMessageService.showErrorMessage).toHaveBeenCalled();
        });

        it('check rules validation passes', function() {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            var rules = [
                {is_valid: false, name: 'invalid_rule'},
                {is_valid: true, name: 'rule_1'},
                {is_valid: true, name: 'rule_2'},
                {is_valid: true, name: 'rule_3'}
            ];

            var validationResult = SignatureImportHelperService.validateRules(rules, true);
            expect(validationResult.result).toBeTruthy();
            expect(validationResult.pRuleId).toBe('');
            expect(CommonErrorMessageService.showErrorMessage).not.toHaveBeenCalled();
        });

        it('check searching by id', function() {
            var entities = [
                {id: 1}, {id: 2}, {id:3}
            ];

            var foundEntity = SignatureImportHelperService.findEntityById(entities, 2);
            expect(foundEntity.id).toBe(2);
        });

        it('check top level settings updates can not find common', function() {
            var settingsObj = {
                category: null,
                severity: null
            };

            var rules = [
                {uid: 1, category: {id: 1}, severity: {id: 1}},
                {uid: 2, category: {id: 2}, severity: {id: 2}},
                {uid: 3, category: {id: 3}, severity: {id: 3}}
            ];

            var checkboxItems = {1: true, 2: true, 3: true};

            SignatureImportHelperService.updateTopLvlSettings(settingsObj, rules, checkboxItems);
            expect(settingsObj.category).toBe(null);
            expect(settingsObj.severity).toBe(null);
        });

        it('check top level settings updates can find common if non common are unselected', function() {
            var settingsObj = {
                category: null,
                severity: null
            };

            var rules = [
                {uid: 1, category: {id: 1}, severity: {id: 1}},
                {uid: 2, category: {id: 2}, severity: {id: 2}},
                {uid: 3, category: {id: 3}, severity: {id: 3}},
                {uid: 4, category: {id: 1}, severity: {id: 1}}
            ];

            var checkboxItems = {1: true, 4: true};

            SignatureImportHelperService.updateTopLvlSettings(settingsObj, rules, checkboxItems);
            expect(settingsObj.category.id).toBe(1);
            expect(settingsObj.severity.id).toBe(1);
        });

        it('check top level settings updates can find common category', function() {
            var settingsObj = {
                category: null,
                severity: null
            };

            var rules = [
                {uid: 1, category: {id: 1}, severity: {id: 1}},
                {uid: 2, category: {id: 1}, severity: {id: 2}},
                {uid: 3, category: {id: 1}, severity: {id: 3}}
            ];

            var checkboxItems = {1: true, 2: true, 3: true};

            SignatureImportHelperService.updateTopLvlSettings(settingsObj, rules, checkboxItems);
            expect(settingsObj.category.id).toBe(1);
            expect(settingsObj.severity).toBe(null);
        });

        it('check top level settings updates can find common severity', function() {
            var settingsObj = {
                category: null,
                severity: null
            };

            var rules = [
                {uid: 1, category: {id: 1}, severity: {id: 1}},
                {uid: 2, category: {id: 2}, severity: {id: 1}},
                {uid: 3, category: {id: 3}, severity: {id: 1}}
            ];

            var checkboxItems = {1: true, 2: true, 3: true};

            SignatureImportHelperService.updateTopLvlSettings(settingsObj, rules, checkboxItems);
            expect(settingsObj.category).toBe(null);
            expect(settingsObj.severity.id).toBe(1);
        });
    });

    describe('SignatureCategoriesModel methods', function() {
        beforeEach(function () {

            //need both url versions here to match Dev and Prod testing
            $httpBackend.whenGET(function (url) {
                return url.indexOf('signatures.categories.lite.json') > 0 ||
                    url.indexOf('signature_categories/updates') > 0;
            }).respond(
                {
                    objects: [
                        {
                            id: 1,
                            name: 'Imported',
                            signatures_count: 1050
                        },
                        {
                            id: 2,
                            name: 'Primary category',
                            signatures_count: 230
                        },
                        {
                            id: 3,
                            name: 'Secondary category',
                            signatures_count: 83
                        }
                    ]
                }
            );

            $httpBackend.whenGET(function (url) {
                return url.indexOf('policy.detail.signatures.json?id=1&page=1') > 0 ||
                    url.indexOf('signature_categories/1/signatures?page=1') > 0;
            }).respond(
                {
                    total_pages: 2,
                    objects: [
                        {
                            id: 1,
                            name: 'fake signature',
                            category_id: 1
                        }
                    ],
                    page: 1
                }
            );

            $httpBackend.whenGET(function (url) {
                return url.indexOf('policy.detail.signatures.json?id=1&page=2') > 0 ||
                    url.indexOf('signature_categories/1/signatures?page=2') > 0;
            }).respond(
                {
                    total_pages: 2,
                    objects: [
                        {
                            id: 1,
                            name: 'fake signature',
                            category_id: 1
                        }
                    ],
                    page: 2
                }
            );

            $httpBackend.whenGET(function (url) {
                return url.indexOf('policy.detail.signatures.json?id=2') > 0 ||
                    url.indexOf('policy.detail.signatures.json?id=3') > 0 ||
                    url.indexOf('signature_categories/2/signatures') > 0 ||
                    url.indexOf('signature_categories/3/signatures') > 0;
            }).respond(
                {
                    total_pages: 1,
                    objects: [
                        {
                            id: 1,
                            name: 'fake signature',
                            category_id: 1
                        }
                    ],
                    page: 1
                }
            );

            $rootScope.$digest();
        });

        it('check signatures and categories are loaded', function () {
            var progressValues = {};
            var signatureModel = SignatureCategoriesModel.getData(progressValues).then(function(loadedData){
                expect(loadedData.length).toBe(3);
                expect(loadedData[0].signatures.length).toBe(2);
                expect(loadedData[1].signatures.length).toBe(1);
                expect(loadedData[2].signatures.length).toBe(1);
            });
            $httpBackend.flush();
        });

        describe('SignatureSelectController methods check', function () {
            var $scope, controller, selectedCategories, selectedSignatures;

            beforeEach(function () {
                $scope = $rootScope;

                controller = $controller('SignatureSelectController', { $scope: $scope });

                $scope.preselectionModel = [];

                selectedCategories = '';
                $scope.categoriesSelectionUpdater.updateSelection = function(idsStr){selectedCategories = idsStr;};

                selectedSignatures = '';
                $scope.signaturesSelectionUpdater.updateSelection = function(idsStr){selectedSignatures = idsStr;};

                $httpBackend.flush();
            });

            it('check controller initialization', function () {
                expect($scope.categoriesSelectionUpdater).not.toBeUndefined();
                expect($scope.signaturesSelectionUpdater).not.toBeUndefined();
                expect($scope.isSignatureSelectionEnabled).toBeFalsy();
                expect($scope.availableSignatures).not.toBeUndefined();
                expect($scope.currentlySelectedCategoryIDs).not.toBeUndefined();
                expect($scope.currentlySelectedSignatureIDs).not.toBeUndefined();
            });

            it('check import modal can be opened', function() {
                spyOn(CommonModalService, 'show');
                $scope.openImportSignatureModal();
                expect(CommonModalService.show).toHaveBeenCalled();
            });

            it('check new signature modal can be opened', function() {
                spyOn(CommonModalService, 'show');
                $scope.addNewSignature();
                expect(CommonModalService.show).toHaveBeenCalled();
            });

            it('check reload categories preselects newly added category and keeps selected signatures', function() {
                $scope.currentlySelectedSignatureIDs = {1: true, 2: true, 3: true};

                $scope.selectionMode = 'signatures';
                $scope.changeSelectionMode();

                $scope.reloadSignatureCategories({id: 1});
                $httpBackend.flush();
                expect(selectedCategories).toBe('1');
                expect(selectedSignatures).toBe('1,2,3');
            });

            it('check categories selection populates selected signatures', function() {
                $scope.selectionMode = 'categories';
                $scope.changeSelectionMode();

                expect(Object.keys($scope.currentlySelectedCategoryIDs).length).toBe(0);
                expect(Object.keys($scope.currentlySelectedSignatureIDs).length).toBe(0);
                expect($scope.selectionModel.length).toBe(0);

                $scope.categorySelectionChange({2: true});
                expect(Object.keys($scope.currentlySelectedCategoryIDs).length).toBe(1);

                expect($scope.selectionModel.length).toBe(1);

                $scope.clearAllSelected();
                expect($scope.selectionModel.length).toBe(0);
                expect(selectedCategories).toBe('');
            });

            it('check categories selection populates available signatures', function() {
                $scope.selectionMode = 'signatures';
                $scope.changeSelectionMode();

                expect(Object.keys($scope.currentlySelectedCategoryIDs).length).toBe(0);
                expect(Object.keys($scope.currentlySelectedSignatureIDs).length).toBe(0);
                expect($scope.availableSignatures.length).toBe(0);

                $scope.categorySelectionChange({2: true});
                expect(Object.keys($scope.currentlySelectedCategoryIDs).length).toBe(1);

                expect($scope.availableSignatures.length).toBe(1);
                expect($scope.selectionModel.length).toBe(0);

                $scope.signaturesSelectionChange({1: true});
                expect(Object.keys($scope.currentlySelectedSignatureIDs).length).toBe(1);
                expect($scope.selectionModel.length).toBe(1);

                $scope.clearAllSelected();
                expect($scope.selectionModel.length).toBe(0);
                expect(selectedSignatures).toBe('');
            });

            it('check single signature selection remove', function() {
                $scope.selectionMode = 'signatures';
                $scope.changeSelectionMode();

                expect(Object.keys($scope.currentlySelectedCategoryIDs).length).toBe(0);
                expect(Object.keys($scope.currentlySelectedSignatureIDs).length).toBe(0);
                expect($scope.availableSignatures.length).toBe(0);

                $scope.categorySelectionChange({1: true});

                $scope.signaturesSelectionChange({1: true});
                expect($scope.selectionModel.length).toBe(1);

                $scope.removeSelection(0);
                expect($scope.selectionModel.length).toBe(1);

                $scope.removeSelection(1);
                expect($scope.selectionModel.length).toBe(0);
            });

            it('check preselection', function() {
                $scope.selectionMode = 'signatures';
                $scope.changeSelectionMode();
                expect($scope.selectionModel.length).toBe(0);

                $scope.preselectionModel = [{id: 1, category_id: 2}];

                $scope.checkPreselection();
                expect(selectedCategories).toBe('2');
                expect(selectedSignatures).toBe('1');
            });

        });

    });

    describe('SignatureNewCategoryController methods check', function () {
        var $scope, controller, isSubmitted, isCancelled;

        beforeEach(function () {
            $scope = $rootScope;
            isSubmitted = false;
            isCancelled = false;

            var fakeModal = {
                opened: {
                    then: function(){}
                },
                close: function(){},
                dismiss: function(){}
            };

            controller = $controller('SignatureNewCategoryController', { $scope: $scope, $modalInstance: fakeModal,
                existingCategories: [],
                cancelCallback: function(){
                    isCancelled = true;
                },
                submitCallback: function(){
                    isSubmitted = true;
                }});
        });

        it('check controller initialization', function () {
            expect($scope.model.data).not.toBeUndefined();
            expect($scope.model.validation).not.toBeUndefined();
        });

        it('check validations', function () {
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureCategoryName'});
            expect($scope.model.validation.name).toBeTruthy();
        });

        it('check signature category creation', function () {
            expect(isSubmitted).toBeFalsy();
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureCategoryName'});

            $scope.model.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signatures.categories.item.json') > 0 || url.indexOf('signature_categories') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.saveSignatureCategory();
            $httpBackend.flush();

            expect(isSubmitted).toBeTruthy();
        });

        it('check can be cancelled', function () {
            expect(isCancelled).toBeFalsy();

            $scope.closeCategoryModal();

            expect(isCancelled).toBeTruthy();
        });

    });

    describe('SignatureNewSeverityController methods check', function () {
        var $scope, controller, isSubmitted, isCancelled;

        beforeEach(function () {
            $scope = $rootScope;
            isSubmitted = false;
            isCancelled = false;

            var fakeModal = {
                opened: {
                    then: function(){}
                },
                close: function(){},
                dismiss: function(){}
            };

            controller = $controller('SignatureNewSeverityController', { $scope: $scope, $modalInstance: fakeModal,
                existingSeverities: [],
                cancelCallback: function(){
                    isCancelled = true;
                },
                submitCallback: function(){
                    isSubmitted = true;
                }});
        });

        it('check controller initialization', function () {
            expect($scope.model.data).not.toBeUndefined();
            expect($scope.model.validation).not.toBeUndefined();
        });

        it('check validations', function () {
            expect($scope.model.validation.name).toBeFalsy();
            expect($scope.model.validation.priority).toBeFalsy();
            expect($scope.model.validation.bgClr).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityName'});
            expect($scope.model.validation.name).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityPriority'});
            expect($scope.model.validation.priority).toBeTruthy();

            $scope.$emit('input.text.validation.processed', {isValid: false, name: 'signatureSeverityBgColor'});
            expect($scope.model.validation.bgClr).toBeFalsy();
        });

        it('check signature severity creation', function () {
            expect(isSubmitted).toBeFalsy();
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityName'});
            $scope.$emit('input.text.validation.processed', {isValid: true, name: 'signatureSeverityPriority'});

            $scope.model.data.name = 'new';

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).name == 'new';
            }).respond(
                {}
            );

            $scope.saveSignatureSeverity();
            $httpBackend.flush();

            expect(isSubmitted).toBeTruthy();
        });

        it('check can be cancelled', function () {
            expect(isCancelled).toBeFalsy();

            $scope.closeCategoryModal();

            expect(isCancelled).toBeTruthy();
        });
    });

    describe('ImportSignatureSaveController methods check', function () {
        var $scope, controller, isSubmitted, isCancelled, isBackAction, defaultCategoryId;

        beforeEach(function () {
            $scope = $rootScope;
            isSubmitted = false;
            isCancelled = false;
            isBackAction = false;
            defaultCategoryId = 1;

            var fakeModal = {
                opened: {
                    then: function () {
                    }
                },
                close: function () {
                },
                dismiss: function () {
                }
            };

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signatures.categories.lite.json') > 0 || url.indexOf('signature_categories') > 0;
            }).respond(
                getJSONFixture('json-mocks/signatures.categories.lite.json')
            );

            $httpBackend.whenGET(function(url) {
                return url.indexOf('signature.severities.json') > 0 || url.indexOf('signature_severities') > 0;
            }).respond(
                getJSONFixture('json-mocks/signature.severities.json')
            );

            $httpBackend.whenPOST(function(url) {
                return url.indexOf('import_preview.json') > 0 || url.indexOf('signatures/import/preview') > 0;
            }).respond(
                getJSONFixture('json-mocks/import_preview.json')
            );

            controller = $controller('ImportSignatureSaveController', { $scope: $scope, $modalInstance: fakeModal,
                selectedCategory: {id: defaultCategoryId},
                selectedFile: {},
                importPreviewCancelled: function () {
                    isCancelled = true;
                },
                importPreviewSubmitted: function () {
                    isSubmitted = true;
                },
                importPreviewBackHandler: function () {
                    isBackAction = true;
                }});
        });

        it('check controller initialization', function () {
            expect($scope.importPreviewData).not.toBeUndefined();
            expect($scope.checkboxes).not.toBeUndefined();
            expect($scope.states).not.toBeUndefined();
            expect($scope.counters).not.toBeUndefined();
            expect($scope.displayedRules).not.toBeUndefined();
            expect($scope.topLvlSettings).not.toBeUndefined();
            expect($scope.values).not.toBeUndefined();
        });

        it('check new category modal opens', function() {
            expect($scope.isSubModalShown).toBeFalsy();

            spyOn(CommonModalService, 'show');
            $scope.openNewCategoryDialog();
            expect(CommonModalService.show).toHaveBeenCalled();

            expect($scope.isSubModalShown).toBeTruthy();

            $scope.newCategoryCreated({id: 3});
            expect($scope.isSubModalShown).toBeFalsy();
        });

        it('check new severity modal opens', function() {
            expect($scope.isSubModalShown).toBeFalsy();

            spyOn(CommonModalService, 'show');
            $scope.openNewSeverityDialog();
            expect(CommonModalService.show).toHaveBeenCalled();

            expect($scope.isSubModalShown).toBeTruthy();

            $scope.newSeverityCreated({id: 3});
            expect($scope.isSubModalShown).toBeFalsy();
        });

        it('check modal actions', function() {
            expect(isSubmitted).toBeFalsy();
            expect(isCancelled).toBeFalsy();
            expect(isBackAction).toBeFalsy();

            $scope.navToPreviousStep();
            expect(isBackAction).toBeTruthy();

            $scope.closeImportSaveModal();
            expect(isCancelled).toBeTruthy();

            $scope.submitDialog();
            expect(isSubmitted).toBeTruthy();
        });

        it('check file upload for preview', function () {
            $scope.loadServiceDataAndUploadImport();
            $httpBackend.flush();

            expect($scope.values.severities[0].id).toBe(-1);
            expect($scope.values.defaultCategory.id).toBe(defaultCategoryId);
            expect($scope.counters.validRulesCount).toBeGreaterThan(0);
            expect($scope.displayedRules.length).toBeGreaterThan(0);
            expect($scope.checkImportValidationPassed()).toBeTruthy();
        });

        it('check set rules upload', function () {
            $scope.loadServiceDataAndUploadImport();
            $httpBackend.flush();

            $httpBackend.expectPOST(function(url) {
                return url.indexOf('signature.import.result.json') > 0 || url.indexOf('signatures/import') > 0;
            }, function(dataStr) {
                return JSON.parse(dataStr).rules.length > 0 && JSON.parse(dataStr).editable == true;
            }).respond(
                getJSONFixture('json-mocks/signature.import.result.json')
            );

            $scope.saveImport();
            $httpBackend.flush();
        });
    });

    describe('ImportSignatureController methods check', function () {
        var $scope, controller;

        beforeEach(function () {
            $scope = $rootScope;

            var fakeModal = {
                opened: {
                    then: function () {
                    }
                },
                close: function () {
                },
                dismiss: function () {
                }
            };

            controller = $controller('ImportSignatureController', { $scope: $scope, $modalInstance: fakeModal,
                selectedCategory: {id: 1}});

        });

        it('check import error if no file selected', function () {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            spyOn($scope, 'processImport');

            $scope.importSignature();

            expect(CommonErrorMessageService.showErrorMessage).toHaveBeenCalled();
            expect($scope.processImport).not.toHaveBeenCalled();
        });

        it('check import error if selected file is too big', function () {
            spyOn(CommonAlertMessageService, 'showMessage');
            spyOn($scope, 'processImport');
            $scope.model.data.selectedFile = {
                size: 1048577
            };

            $scope.importSignature();

            expect(CommonAlertMessageService.showMessage).toHaveBeenCalled();
            expect($scope.processImport).not.toHaveBeenCalled();
        });

        it('check import preview passes', function () {
            spyOn(CommonModalService, 'show');

            $scope.processImport();

            expect(CommonModalService.show).toHaveBeenCalled();
        });

    });

});
