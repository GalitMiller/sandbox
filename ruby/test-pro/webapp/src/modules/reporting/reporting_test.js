describe('bricata ui grid reporting', function() {

    var $controller,
        $rootScope,
        $location,
        $httpBackend,
        BricataUris,
        BroadcastService,
        CommonErrorMessageService;

    beforeEach(module('BPACApp'));

    beforeEach(inject(function(_$controller_, _$rootScope_, _$location_, _$httpBackend_,
                               _BricataUris_, _BroadcastService_, _CommonErrorMessageService_){
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $location = _$location_;
        $httpBackend = _$httpBackend_;
        BricataUris = _BricataUris_;
        BroadcastService = _BroadcastService_;
        CommonErrorMessageService = _CommonErrorMessageService_;

        $httpBackend.whenGET(function(url) {
            return url.indexOf("api/v1/current_user") > 0 ||
                url.indexOf("config/app_conf.json") === 0 ||
                url.indexOf("userinfo.json") > 0;
        }).respond(
            {}
        );
    }));

    describe('GridCommonControl methods for reporting', function() {
        var $scope, controller;

        beforeEach(function() {
            $scope = $rootScope;
            $controller('MainController', { $scope: $scope });
        });

        it('check policies configuration exists and is correct', function() {
            $location.path('fake'+BricataUris.pages.policiesPage);
            controller = $controller('GridCommonControl', { $scope: $scope });
            expect($scope.configuration).not.toBeNull();
            expect($scope.configuration.url).toEqual(BricataUris.policyItems);
        });

        it('check inactive-sensors configuration exists', function() {
            $location.path('fake'+BricataUris.pages.inactiveSensorPage);
            controller = $controller('GridCommonControl', { $scope: $scope });
            expect($scope.configuration).not.toBeNull();
            expect($scope.configuration.url).toEqual(BricataUris.inactiveSensorItems);
        });

        it('check grid event handling mechanism', function() {
            BroadcastService.changeTopLevelMessage({
                item: {},
                id: 0,
                action: 'edit'
            });
            $location.path('fake'+BricataUris.pages.policiesPage);
            controller = $controller('GridCommonControl', { $scope: $scope });
            $scope.handleTopLvlMsgChange(true);
            expect($scope.changedObject).not.toBeNull();
            expect($scope.changedObject.action).toEqual('edit');
        });
    });

    describe('GridController methods for reporting', function() {
        var $scope, controller;

        beforeEach(function() {
            $scope = $rootScope;
        });

        it('check grid filter query builder', function() {
            $location.path('fake'+BricataUris.pages.policiesPage);
            controller = $controller('GridController', { $scope: $scope });

            $scope.sorting = {field: 'name', direction: 'asc'};
            $scope.filterData = [{"or":[
                {"name":"name","op":"like","val":"%test%"},
                {"name":"description","op":"like","val":"%test%"}]}];
            expect($scope.prepareQueryData()).toEqual('{"order_by":[{"field":"name","direction":"asc"}],'+
                '"filters":[{"or":[{"name":"name","op":"like","val":"%test%"},'+
                '{"name":"description","op":"like","val":"%test%"}]}]}');
        });
    });

    describe('ExportDialogController methods for reporting', function() {
        var $scope, controller, isAllSelected, isCancelled;

        beforeEach(function() {
            $scope = $rootScope;
            isAllSelected = false;
            isCancelled = false;

            var fakeModal = {
                opened: {
                    then: function () {
                    }
                },
                close: function () {
                },
                dismiss: function () {
                    isCancelled = true;
                }
            };

            controller = $controller('ExportDialogController', { $scope: $scope, $modalInstance: fakeModal,
                labels: [], selectedCount: 0,
                exportHandler: function(isAll){
                    isAllSelected = isAll;
                }});
        });

        it('check controller initialization', function () {
            expect($scope.labels).not.toBeUndefined();
            expect($scope.selectedCount).not.toBeUndefined();
            expect($scope.model).not.toBeUndefined();
        });

        it('check can be closed', function () {
            expect(isCancelled).toBeFalsy();
            $scope.closeExportModal();
            expect(isCancelled).toBeTruthy();
        });

        it('check export with all selection', function () {
            expect(isAllSelected).toBeFalsy();
            $scope.performExport();
            expect(isAllSelected).toBeTruthy();
        });

        it('check export with single selection', function () {
            $scope.model.type = '';

            expect(isAllSelected).toBeFalsy();
            $scope.performExport();
            expect(isAllSelected).toBeFalsy();
        });
    });

    describe('ImportDialogController methods for reporting', function() {
        var $scope, controller, isClosed, isCancelled, importFile;

        beforeEach(function() {
            $scope = $rootScope;
            isClosed = false;
            isCancelled = false;
            importFile = {};

            var fakeModal = {
                opened: {
                    then: function () {
                    }
                },
                close: function () {
                    isClosed = true;
                },
                dismiss: function () {
                    isCancelled = true;
                }
            };

            controller = $controller('ImportDialogController', { $scope: $scope, $modalInstance: fakeModal,
                labels: [], selectedCount: 0,
                importMethod: function(file) {
                    importFile = file;
                    return {
                        then: function (func) {
                            func.call(null, {});
                        }
                    }
                }});
        });

        it('check controller initialization', function () {
            expect($scope.labels).not.toBeUndefined();
            expect($scope.states).not.toBeUndefined();
            expect($scope.selectedFile).not.toBeUndefined();
            expect($scope.failures).not.toBeUndefined();
        });

        it('check file selection', function () {
            expect($scope.selectedFile).toBe(null);
            $scope.$emit('file.selected', {name: 'test'});
            expect($scope.selectedFile.name).toBe('test');
        });

        it('check can be closed', function () {
            expect(isClosed).toBeFalsy();
            $scope.submitDialog();
            expect(isClosed).toBeTruthy();
        });

        it('check can be cancelled', function () {
            expect(isCancelled).toBeFalsy();
            $scope.closeImportModal();
            expect(isCancelled).toBeTruthy();
        });

        it('check import fails', function () {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            $scope.processImport();
            expect(CommonErrorMessageService.showErrorMessage).toHaveBeenCalled();
        });

        it('check import passes', function () {
            spyOn(CommonErrorMessageService, 'showErrorMessage');
            $scope.$emit('file.selected', {name: 'test'});
            $scope.processImport();
            expect(importFile.name).toBe('test');
            expect(CommonErrorMessageService.showErrorMessage).not.toHaveBeenCalled();
        });
    });
});