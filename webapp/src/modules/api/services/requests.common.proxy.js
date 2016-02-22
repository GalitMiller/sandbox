angular.module('bricata.ui.api')
    .service('CommonProxyForRequests', ['$q', '$location', 'BricataUris',
        function($q, $location, BricataUris){
            var pendingPromises = [];

            var removePendingPromiseWhenCompleted = function(deferred){
                var index = pendingPromises.indexOf(deferred);
                if (index > -1) {
                    pendingPromises.splice(index, 1);
                }
            };

            this.getDecoratedPromise = function (promise, isTopLvlData, sortingObjectsField) {
                var deferred = $q.defer();

                promise.then(function (receivedData) {
                    if (isTopLvlData) {
                        deferred.resolve(receivedData);
                        removePendingPromiseWhenCompleted(deferred);
                    } else {
                        if (sortingObjectsField) {
                            receivedData.objects.sort(function (a, b) {
                                if (a[sortingObjectsField] > b[sortingObjectsField]) {
                                    return 1;
                                }
                                if (a[sortingObjectsField] < b[sortingObjectsField]) {
                                    return -1;
                                }
                                return 0;
                            });
                        }

                        deferred.resolve(receivedData.objects);
                        removePendingPromiseWhenCompleted(deferred);
                    }
                }, function (error) {
                    if (error.status === 401) {
                        $location.path(BricataUris.loginPageLink);
                    } else {
                        deferred.reject(error);
                        removePendingPromiseWhenCompleted(deferred);
                    }
                });

                pendingPromises.push(deferred);

                return deferred.promise;
            };

            this.cancelAllPendingRequests = function(){
                angular.forEach(pendingPromises, function (pendingPromise) {
                    pendingPromise.reject({isCancelled: true});
                });
                pendingPromises = [];
            };

        }]);
