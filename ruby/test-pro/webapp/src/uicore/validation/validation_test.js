describe('bricata core validation', function() {

    var $controller,
        $rootScope,
        $compile,
        element;

    beforeEach(module('jm.i18next'));
    beforeEach(module('bricata.uicore.validation'));

    beforeEach(inject(function (_$controller_, _$rootScope_, _$compile_) {
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $compile = _$compile_;
    }));

    describe('inputValidation validation directive', function() {
        var $scope;

        beforeEach(function() {
            $scope = $rootScope;

            $scope.dataModel = '';

            element = angular.element('<textarea ng-model="dataModel" input-validation ' +
            'required ng-minlength="4" ng-maxlength="7" ng-pattern="/^\\d+$/" ' +
            'tooltip=""></textarea>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check inputValidation directive mechanism', function () {
            var isolated = element.isolateScope();

            element.val('').trigger('input');
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.fieldRequired');

            element.val('bob').trigger('input');
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.tooSmall');

            element.val('bob brown').trigger('input');
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.tooLong');

            element.val('bobby').trigger('input');
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.incorrectValue');

            element.val('1234').trigger('input');
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('');
        });

        it('check inputValidation directive adds listeners on event', function () {
            var isolated = element.isolateScope();

            expect(isolated.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation');
            expect(isolated.listenersAttached).toBeTruthy();
        });
    });

    describe('common check box validation directive fails validation', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;
        });

        it('check common check box directive mechanism fails', function () {
            element = angular.element('<div checkboxes-validation tooltip=""><input type="checkbox"/>' +
                '<input type="checkbox"/><input type="checkbox"/></div>');

            $compile(element)($scope);
            $scope.$digest();

            var isolated = element.isolateScope();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.checkboxesNotSelected');
        });

        it('check common check box directive mechanism pass', function () {
            element = angular.element('<div checkboxes-validation tooltip=""><input type="checkbox" checked/>' +
                '<input type="checkbox"/><input type="checkbox"/></div>');

            $compile(element)($scope);
            $scope.$digest();

            var isolated = element.isolateScope();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('');
        });

        it('check common check box directive adds listeners on event', function () {
            element = angular.element('<div checkboxes-validation tooltip=""><input type="checkbox" checked/>' +
                '<input type="checkbox"/><input type="checkbox"/></div>');

            $compile(element)($scope);
            $scope.$digest();

            var isolated = element.isolateScope();

            expect(isolated.listenersAttached).toBeFalsy();
            $rootScope.$emit('run.validation');
            expect(isolated.listenersAttached).toBeTruthy();
        });
    });

    describe('check referenceInputValidation validation directive', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;
            $scope.model = [
                {typeId: 1, value: 'test'}
            ];
            $scope.flag = true;
            element = angular.element('<div reference-input-validation rows-model="model" tooltip="" ' +
                'no-duplicated-reference-flag="flag"></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check referenceInputValidation directive mechanism passes', function () {
            var isolated = element.isolateScope();

            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('');
            expect(isolated.noDuplicatedReferenceFlag).toBeTruthy();
        });

        it('check referenceInputValidation directive mechanism for searching empty inputs', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {typeId: 1, value: ''}
            ];
            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.emptyReferenceValue');
            expect(isolated.noDuplicatedReferenceFlag).toBeTruthy();

            $scope.model = [
                {typeId: null, value: 'test'}
            ];
            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.emptyReferenceValue');
            expect(isolated.noDuplicatedReferenceFlag).toBeTruthy();

            $scope.model = [
                {typeId: 1, value: 'test1'},
                {typeId: null, value: 'test2'}
            ];
            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.emptyReferenceValue');
            expect(isolated.noDuplicatedReferenceFlag).toBeTruthy();
        });

        it('check referenceInputValidation directive mechanism for searching duplicates', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {typeId: 1, value: 'test1'},
                {typeId: 1, value: 'test1'}
            ];
            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.duplicatedReference');
            expect(isolated.noDuplicatedReferenceFlag).toBeFalsy();

            $scope.model = [
                {typeId: 1, value: 'test1'},
                {typeId: 1, value: 'test2'}
            ];
            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('');
            expect(isolated.noDuplicatedReferenceFlag).toBeTruthy();
        });
    });

    describe('check policySelectValidation validation directive', function() {
        var $scope, topMsg;

        beforeEach(function () {
            $scope = $rootScope;
            $scope.model = [
                {policy: {id: 1}, action: {value: 'test'}}
            ];
            $scope.flag = false;
            $scope.msgUpdate = function(msg){
                topMsg = msg;
            };
            element = angular.element('<div policy-select-validation rows-model="model" tooltip="" ' +
                'duplicated-flag="flag" top-lvl-err-msg-update="msgUpdate"></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check policySelectValidation directive mechanism passes', function () {
            var isolated = element.isolateScope();

            isolated.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeFalsy();
            expect(isolated.duplicatedFlag).toBeFalsy();
            expect(topMsg).toBe('');
        });

        it('check policySelectValidation directive searches empty inputs', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {policy: {}, action: {value: 'test'}}
            ];

            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(isolated.duplicatedFlag).toBeFalsy();
            expect(topMsg).toBe('validationErrors.errorEmptyCompositeInput');
        });

        it('check policySelectValidation directive searches duplicates', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {policy: {id: 1}, action: {value: 'test'}},
                {policy: {id: 1}, action: {value: 'test'}}
            ];

            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(isolated.duplicatedFlag).toBeTruthy();
            expect(topMsg).toBe('applyPolicyModal.errorDuplicatedPolicies');
        });

        it('check policySelectValidation directive adds listeners on event', function () {
            var isolated = element.isolateScope();

            expect(isolated.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation');
            expect(isolated.listenersAttached).toBeTruthy();
        });
    });

    describe('check sensorSelectValidation validation directive', function() {
        var $scope, topMsg;

        beforeEach(function () {
            $scope = $rootScope;
            $scope.model = [
                {sensor: {name: 'sensor 1'}, interface: {name: 'eth0'}}
            ];
            $scope.flag = false;
            $scope.msgUpdate = function(msg){
                topMsg = msg;
            };
            element = angular.element('<div sensor-select-validation rows-model="model" tooltip="" ' +
                'duplicated-flag="flag" top-lvl-err-msg-update="msgUpdate"></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check sensorSelectValidation directive mechanism passes', function () {
            var isolated = element.isolateScope();

            isolated.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeFalsy();
            expect(isolated.duplicatedFlag).toBeFalsy();
            expect(topMsg).toBe('');
        });

        it('check sensorSelectValidation directive searches empty inputs', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {sensor: {name: ''}, interface: {name: 'eth0'}}
            ];

            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(isolated.duplicatedFlag).toBeFalsy();
            expect(topMsg).toBe('validationErrors.errorEmptyCompositeInput');
        });

        it('check sensorSelectValidation directive searches duplicates', function () {
            var isolated = element.isolateScope();

            $scope.model = [
                {sensor: {name: 'sensor 1'}, interface: {name: 'eth0'}},
                {sensor: {name: 'sensor 1'}, interface: {name: 'eth0'}}
            ];

            $rootScope.$apply();
            isolated.performValidation();
            $rootScope.$apply();
            expect(isolated.duplicatedFlag).toBeTruthy();
            expect(topMsg).toBe('applyPolicyModal.errorDuplicatedInterfaces');
        });

        it('check sensorSelectValidation directive adds listeners on event', function () {
            var isolated = element.isolateScope();

            expect(isolated.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation');
            expect(isolated.listenersAttached).toBeTruthy();
        });
    });

    describe('signatureSelectValidation validation directive', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;

            $scope.selectionModel = [];

            element = angular.element('<div><div signature-select-validation tooltip=""></div></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check signatureSelectValidation directive mechanism fails', function () {
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeTruthy();
        });

        it('check signatureSelectValidation directive mechanism passes', function () {
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeTruthy();

            expect($scope.listenersAttached).toBeFalsy();
            $scope.selectionModel = [{}];
            $rootScope.$apply();
            expect($scope.listenersAttached).toBeTruthy();

            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeFalsy();
        });

        it('check signatureSelectValidation directive adds listeners on event', function () {
            expect($scope.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation', {group: 'test'});
            expect($scope.listenersAttached).toBeFalsy();

            $scope.$emit('run.validation');
            expect($scope.listenersAttached).toBeTruthy();
        });
    });

    describe('ipInputValidation validation directive', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;

            $scope.selectedIpAddress = {
                ip: '',
                anyIp: false
            };

            $scope.selectedPort = {
                port: '',
                anyPort: false
            };

            element = angular.element('<div ip-input-validation tooltip=""></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check ipInputValidation directive mechanism fails', function () {
            expect(element.attr('tooltip')).toBe('');

            $scope.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.ipValueIsEmpty');

            $scope.selectedIpAddress.anyIp = true;
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('validationErrors.portValueIsEmpty');
        });

        it('check ipInputValidation directive mechanism passes', function () {
            $scope.selectedIpAddress.anyIp = true;
            $scope.selectedPort.anyPort = true;

            $scope.performValidation();
            $rootScope.$apply();
            expect(element.attr('tooltip')).toBe('');
        });

        it('check ipInputValidation triggers validation on top level event', function () {
            spyOn($scope ,'scheduleValidation');
            $scope.$emit('run.validation');
            expect($scope.scheduleValidation).toHaveBeenCalled();
        });

        it('check ipInputValidation triggers validation on text validation level event', function () {
            spyOn($scope ,'scheduleValidation');
            $scope.$emit('input.text.validation.processed');
            expect($scope.scheduleValidation).toHaveBeenCalled();
        });
    });

    describe('colorPickerValidation validation directive', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;

            $scope.selectedColor = '';

            element = angular.element('<div color-picker-validation tooltip=""></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check colorPickerValidation directive mechanism fails with empty color', function () {
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeTruthy();
        });

        it('check colorPickerValidation directive mechanism fails with invalid color', function () {
            $scope.selectedColor = '#ad';
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeTruthy();
        });

        it('check colorPickerValidation directive mechanism passes', function () {
            $scope.selectedColor = '#adc';
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeFalsy();
        });

        it('check colorPickerValidation directive adds listeners on event', function () {
            expect($scope.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation');
            expect($scope.listenersAttached).toBeTruthy();
        });
    });

    describe('commonSelectValidation validation directive', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;

            $scope.validationEnabled = true;
            $scope.lblField = 'testField';
            $scope.ngModel = {};

            element = angular.element('<div common-select-validation tooltip=""></div>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check commonSelectValidation directive mechanism fails', function () {
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeTruthy();
        });

        it('check commonSelectValidation directive mechanism passes', function () {
            $scope.ngModel.testField = 'test';
            $scope.performValidation();
            $rootScope.$apply();
            expect(element.hasClass('has-error')).toBeFalsy();
        });

        it('check commonSelectValidation directive adds listeners on event', function () {
            expect($scope.listenersAttached).toBeFalsy();
            $scope.$emit('run.validation');
            expect($scope.listenersAttached).toBeTruthy();
        });
    });

});