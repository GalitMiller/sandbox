angular.module('bricata.uicore.validation')
    .factory("ValidationService", ["$timeout",
        function ($timeout) {
            return {
                showErrorHint: function(attributes, elementWithClass, elementWithTooltip, tooltipTxt, isTopLvlUpdate) {
                    if (attributes.tooltip !== tooltipTxt) {

                        if (!isTopLvlUpdate) {
                            attributes.$set('tooltip', tooltipTxt);
                        }

                        if (elementWithClass) {
                            elementWithClass.addClass('has-error');
                        }
                        elementWithTooltip.triggerHandler('validationfailed');
                    }
                },

                hideErrorHint: function(attributes, elementWithClass, elementWithTooltip, isTopLvlUpdate) {
                    if (attributes.tooltip !== '') {
                        elementWithTooltip.triggerHandler('validationpassed');
                        if (!isTopLvlUpdate) {
                            attributes.$set('tooltip', '');
                        }

                        if (elementWithClass) {
                            elementWithClass.removeClass('has-error');
                        }
                    }
                },

                showTooltip: function(elementWithTooltip) {
                    if (elementWithTooltip.attr('tooltip') !== '') {
                        $timeout(function(){
                            elementWithTooltip.triggerHandler('validationfailed');
                        }, 1, false);
                    }
                },

                validateLater: function(checkTimer, validationCallback) {
                    if (checkTimer) {
                        $timeout.cancel(checkTimer);
                    }
                    return $timeout(function(){
                        validationCallback();
                    }, 333, false);
                },

                pauseValidation: function(element) {
                    $timeout(function(){
                        element.triggerHandler('validationpassed');
                    }, 1, false);
                },

                resumeValidation: function(element) {
                    $timeout(function(){
                        element.triggerHandler('validationfailed');
                    }, 333, false);
                },

                ensureUnique: function(existingNamesQueryPromise, entity, resultCallback) {
                    var isUnique = true;
                    existingNamesQueryPromise.then(function(policies) {
                        var policy;
                        for (var i = 0; i < policies.length; i++) {
                            policy = policies[i];

                            if (policy.name === entity.name && policy.id !== entity.id) {
                                isUnique = false;
                                break;
                            }
                        }

                        resultCallback(isUnique, entity);
                    });
                }
            };

        }]);