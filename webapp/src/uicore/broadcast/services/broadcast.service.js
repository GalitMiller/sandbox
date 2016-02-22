angular.module('bricata.uicore.broadcast')
    .factory('BroadcastService', function () {
        var broadcastService = {};

        broadcastService.messageObject = undefined;

        broadcastService.changeTopLevelMessage = function (msgObj) {
            this.messageObject = msgObj;
        };

        broadcastService.consumeMsg = function () {
            this.messageObject = undefined;
        };

        return broadcastService;
});