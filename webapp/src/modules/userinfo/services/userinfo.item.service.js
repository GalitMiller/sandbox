angular.module('bricata.ui.userinfo')
    .factory('UserInfoItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.userInfo, {}, {
                query: {method: 'GET'}
            });

        }]);