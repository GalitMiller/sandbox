angular.module("bricata.ui.sensors")
    .factory("SensorsDataService",
    ["CommonProxyForRequests", "InactiveSensorItemCount", "SensorItem", "InterfaceItem", "SensorControlItem",
        function(CommonProxyForRequests, InactiveSensorItemCount, SensorItem, InterfaceItem, SensorControlItem){
            var service = {
                getInactiveSensorsCount:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        InactiveSensorItemCount.query().$promise, true);
                },

                getAllSensors:function(){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SensorItem.query().$promise);
                },

                getSensorInterfaces:function(sensorId){
                    return CommonProxyForRequests.getDecoratedPromise(
                        InterfaceItem.query({rowId: sensorId}).$promise);
                },

                activateSensor:function(sensorId, activationData){
                    return CommonProxyForRequests.getDecoratedPromise(
                        SensorControlItem.activate({id: sensorId}, activationData).$promise, true);
                }
            };
            return service;
        }]);