angular.module('bricata.uicore.errormsg')
.service('CommonErrorMessageService', [ 'CommonModalService',
    function(CommonModalService){
        this.showErrorMessage = function(errorTxt, msgObj, errorTitle, callback) {
            var msgTxt = null;
            if (msgObj && msgObj.isCancelled) {
                return;
            }

            if (msgObj) {
                if (msgObj.data && msgObj.data.message) {
                    msgTxt = msgObj.data.message;
                } else if (msgObj.message) {
                    if (angular.isArray(msgObj.message)) {
                        msgTxt = msgObj.message.join('<br><br>');
                    } else {
                        msgTxt = msgObj.message;
                    }
                }
            }
            var modalConfiguration = {
                templateUrl: 'uicore/errormessage/views/error-message-modal.html',
                controller: 'ErrorMessageModalController',
                size: msgTxt ? '' : 'sm',
                resolve: {
                    messageObject: function(){
                        return {
                            text: errorTxt,
                            msg: msgTxt ? msgTxt : '',
                            title: errorTitle ? errorTitle : 'errors.commonTitle'
                        };
                    }
                }
            };

            if (callback) {
                CommonModalService.show(modalConfiguration).then(function () {
                    callback();
                });
            } else {
                CommonModalService.show(modalConfiguration);
            }
        };

    }]);
