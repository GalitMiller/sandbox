angular.module("bricata.uicore.keywordstext")
    .directive('keywordsText', function() {
        return {
            restrict: 'E',
            templateUrl: 'uicore/keywordstext/views/keywords-text.html',
            scope: {
                keywords: "=",
                keywordsValidationEventName: "@",
                keywordsValue: "=",
                validationGroup: "@",
                helpLinkUrl: "@"
            },
            link: function(scope, elem) {
                var textArea = angular.element(elem[0].querySelector('textarea'))[0];
                scope.addKeyword = function(keyword) {
                    var keywordTxt = '';
                    var selectionPos = 0;

                    switch (keyword.format) {
                        case 'int':
                            keywordTxt = ' ' + keyword.value + ':;';
                            selectionPos = 1;
                            break;

                        case 'str':
                            keywordTxt = ' ' + keyword.value + ':"";';
                            selectionPos = 2;
                            break;

                        case 'none':
                            keywordTxt = ' ' + keyword.value + ';';
                            break;
                    }


                    if (textArea.selectionStart || textArea.selectionStart === 0) {
                        var startPos = textArea.selectionStart;
                        var endPos = textArea.selectionEnd;
                        var scrollTop = textArea.scrollTop;
                        textArea.value = textArea.value.substring(0, startPos) +
                            keywordTxt + textArea.value.substring(endPos, textArea.value.length);
                        textArea.focus();
                        textArea.selectionStart = textArea.selectionEnd = startPos + keywordTxt.length - selectionPos;
                        textArea.scrollTop = scrollTop;

                        scope.keywordsValue = textArea.value;
                    }
                };
            }
        };
    });