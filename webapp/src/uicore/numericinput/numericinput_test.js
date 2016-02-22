describe('numeric input check', function() {
    var $compile,
        $rootScope;

    beforeEach(module('bricata.uicore.templates'));
    beforeEach(module('bricata.uicore.numericinput'));

    beforeEach(inject(function(_$compile_, _$rootScope_){
        $compile = _$compile_;
        $rootScope = _$rootScope_;
    }));

    it('numeric input validation', function() {
        $rootScope.model = '';
        var element = $compile('<input type="text" class="form-control"'+
        ' numeric-input maxlength="3" minvalue="1" maxvalue="255" ng-model="model">')($rootScope);
        $rootScope.$digest();

        element.val('test').trigger('input');
        $rootScope.$apply();
        expect(element.val()).toBe('');

        element.val('0').trigger('input');
        $rootScope.$apply();
        expect(element.val()).toBe('1');

        element.val('300').trigger('input');
        $rootScope.$apply();
        expect(element.val()).toBe('255');

        element.val('100').trigger('input');
        $rootScope.$apply();
        expect(element.val()).toBe('100');
    });
});