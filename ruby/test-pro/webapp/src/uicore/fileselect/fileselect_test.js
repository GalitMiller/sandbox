describe('file select check', function() {
    var $compile,
        $rootScope;

    beforeEach(module('bricata.uicore.templates'));
    beforeEach(module('bricata.uicore.fileselect'));

    beforeEach(inject(function(_$compile_, _$rootScope_){
        $compile = _$compile_;
        $rootScope = _$rootScope_;
    }));

    it('we must have input type file', function() {
        var element = $compile("<file-select></file-select>")($rootScope);
        $rootScope.$digest();
        expect(element.html()).toContain('<input type="file">');
    });
});