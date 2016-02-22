angular.module('bricata.uicore.alertmsg')
.service('CommonAlertMessageService', [ 'CommonModalService',
    function(CommonModalService){
        this.showMessage = function(msgTitle, msgTxt, msgDetail, cancelHandler, backHandler) {
            var modalConfiguration = {
                templateUrl: 'uicore/alertmessage/views/alert-message-modal.html',
                controller: 'AlertMessageModalController',
                windowClass: 'alert-msg-modal-window',
                resolve: {
                    messageObject: function(){
                        return {
                            title: msgTitle,
                            text: msgTxt,
                            detail: msgDetail,
                            cancel: cancelHandler,
                            back: backHandler
                        };
                    }
                }
            };

            CommonModalService.show(modalConfiguration);
        };

    }]);
