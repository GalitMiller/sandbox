describe('bricata core search list', function() {

    var $controller,
        $rootScope,
        $compile,
        element;

    beforeEach(module('jm.i18next'));
    beforeEach(module('bricata.uicore.templates'));
    beforeEach(module('bricata.uicore.searchlist'));

    beforeEach(inject(function (_$controller_, _$rootScope_, _$compile_) {
        $controller = _$controller_;
        $rootScope = _$rootScope_.$new();
        $compile = _$compile_;
    }));


    describe('searchListController methods without server side call', function () {
        var $scope, controller, checkedItems;

        beforeEach(function () {
            $scope = $rootScope;

            controller = $controller('searchListController', { $scope: $scope });

            $scope.listModel = {
                entities: [
                    {id: 1, name: '1'},
                    {id: 2, name: '2'},
                    {id: 3, name: '3'}
                ]
            };

            $scope.selectionChanged = function() {
                return function(checkboxItems) {
                    checkedItems = checkboxItems;
                };
            };

            $scope.serverDataCall = function() {
                return undefined;
            };

            $scope.searchedItem = {
                name: ''
            };
        });

        it('check search list selection for all', function () {
            $scope.enableCheckBoxes();
            expect($scope.checkboxes).not.toBe(undefined);

            $scope.runPagination();

            $scope.selectAll({target: {checked: true}});
            expect(checkedItems[1]).toBeTruthy();
            expect(checkedItems[2]).toBeTruthy();
            expect(checkedItems[3]).toBeTruthy();
            expect($scope.selectAllProp).toBeFalsy();

            $scope.selectAll({target: {checked: false}});
            expect(checkedItems[1]).toBeFalsy();
            expect(checkedItems[2]).toBeFalsy();
            expect(checkedItems[3]).toBeFalsy();
            expect($scope.selectAllProp).toBeFalsy();
        });

        it('check search list selection for single item', function () {
            $scope.enableCheckBoxes();
            expect($scope.checkboxes).not.toBe(undefined);

            $scope.runPagination();

            $scope.selectionUpdateHandler ('1,2', true);
            expect(checkedItems[1]).toBeTruthy();
            expect(checkedItems[2]).toBeTruthy();
            expect($scope.selectAllProp).toBeTruthy();

            $scope.selectionUpdateHandler('1', false);
            expect(checkedItems[1]).toBeFalsy();
            expect(checkedItems[2]).toBeTruthy();
            expect($scope.selectAllProp).toBeTruthy();

            $scope.selectionUpdateHandler('', false);
            expect($scope.checkboxes.items).toEqual({});
            expect($scope.selectAllProp).toBeFalsy();

            $scope.selectionUpdateHandler('', true);
            expect(checkedItems[1]).toBeTruthy();
            expect(checkedItems[2]).toBeTruthy();
            expect(checkedItems[3]).toBeTruthy();
            expect($scope.selectAllProp).toBeFalsy();
        });

        it('check search list filtering', function () {
            $scope.searchedItem = {name: 1};
            $scope.filterChangeHandler();

            expect($scope.filteredData.length).toBe(1);
            expect($scope.filteredData[0].id).toBe(1);
            expect($scope.noFilteredData).toBeFalsy();

            $scope.searchedItem = {name: 30};
            $scope.filterChangeHandler();

            expect($scope.filteredData.length).toBe(0);
            expect($scope.noFilteredData).toBeTruthy();
        });

        it('check search list UI pagination', function () {
            $scope.runPagination();
            $scope.pagination.perPage = 2;

            $scope.pagination.currentPage = 1;
            $scope.pageChanged();
            expect($scope.displayedItems.length).toBe(2);

            $scope.pagination.currentPage = 2;
            $scope.pageChanged();
            expect($scope.displayedItems.length).toBe(1);
        });
    });

    describe('searchListController methods with server side call', function () {
        var $scope, controller, checkedItems;

        beforeEach(function () {
            $scope = $rootScope;

            controller = $controller('searchListController', { $scope: $scope });

            $scope.parentObjectId = 'fake';
            $scope.searchedItem = {name: 'fake'};

            $scope.serverDataCall = function() {
                return function(objectId, searchedName, pageNum){
                    return {
                        then: function(handler) {
                            handler.call(null, {
                                num_results: 3,
                                objects: [
                                    {id: 1, name: '1'},
                                    {id: 2, name: '2'},
                                    {id: 3, name: '3'}
                                ]
                            });
                        }
                    }
                };
            };
        });

        it('check search list server side pagination', function () {
            $scope.runPagination();
            expect($scope.displayedItems.length).toBe(3);

            $scope.filterChangeHandler();
            expect($scope.displayedItems.length).toBe(3);
        });

    });

    describe('search list directive', function() {
        var $scope;

        beforeEach(function() {
            $scope = $rootScope;
            $scope.objects = [
                    {id: 1, name: '1'},
                    {id: 2, name: '2'},
                    {id: 3, name: '3'}
                ];
            $scope.selectionUpdater = {};

            element = angular.element('<search-list data="objects" top-lvl-selection-updater="selectionUpdater" ' +
                'signature-icon="checkbox"></search-list>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check search list directive initialization', function () {
            var isolated = element.isolateScope();

            expect(isolated.searchedItem.name).toBe('');
            expect(isolated.displayedQuantity).toBe(undefined);

            isolated.displayedQuantity = 0;
            isolated.searchedItem.name = 'fake';
            $scope.$apply();
            expect(isolated.displayedQuantity).toBe(3);
        });
    });
});