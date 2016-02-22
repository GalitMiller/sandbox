describe('keywords text check', function() {
    var $compile,
        $rootScope,
        element;

    beforeEach(module('jm.i18next'));
    beforeEach(module('bricata.uicore.templates'));
    beforeEach(module('bricata.uicore.keywordstext'));

    beforeEach(inject(function(_$compile_, _$rootScope_){
        $compile = _$compile_;
        $rootScope = _$rootScope_;
    }));

    describe('keywords text methods', function() {
        var $scope;

        beforeEach(function () {
            $scope = $rootScope;
            $scope.txtValue = '';
            $scope.keywords = [
                {
                    "value": "content",
                    "format": "str"
                },
                {
                    "value": "nocase",
                    "format": "none"
                },
                {
                    "value": "depth",
                    "format": "int"
                }
            ];

            element = angular.element('<keywords-text keywords="keywords"' +
                ' keywords-value="txtValue"' +
                ' help-link-url="http://test.com"></keywords-text>');

            $compile(element)($scope);
            $scope.$digest();
        });

        it('check str type keyword', function () {
            var isolated = element.isolateScope();

            expect(isolated.keywordsValue).toBe('');
            isolated.addKeyword(isolated.keywords[0]);
            expect(isolated.keywordsValue).toBe(' content:"";');
        });

        it('check none type keyword', function () {
            var isolated = element.isolateScope();

            expect(isolated.keywordsValue).toBe('');
            isolated.addKeyword(isolated.keywords[1]);
            expect(isolated.keywordsValue).toBe(' nocase;');
        });

        it('check int type keyword', function () {
            var isolated = element.isolateScope();

            expect(isolated.keywordsValue).toBe('');
            isolated.addKeyword(isolated.keywords[2]);
            expect(isolated.keywordsValue).toBe(' depth:;');
        });
    });
});