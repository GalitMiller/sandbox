angular.module("bricata.ui.userinfo")
    .factory("UserInfoService", ["$q", "UserInfoItem",
        function($q, UserInfoItem){
            var userData = {};

            var service = {
                getUserInfo:function(){
                    var randomParam = Math.floor(Math.random() * 100000000000000);
                    var deferred = $q.defer();
                    UserInfoItem.query({_: randomParam}).$promise.then(function (userData){
                        deferred.resolve(userData);
                    }, function() {
                        deferred.reject();
                    });

                    return deferred.promise;
                },
                saveLoadedUserInfo:function(userInfo) {
                    userData = userInfo;
                },
                getSavedUserName:function() {
                    return userData.name;
                }
            };
            return service;
        }]);