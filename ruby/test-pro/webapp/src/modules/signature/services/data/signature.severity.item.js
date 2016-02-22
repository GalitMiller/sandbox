angular.module('bricata.ui.signature')
    .factory('SignatureSeverityItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.signatureSeverity, {}, {
                query: {method:'GET'},
                save: {method:'POST'}
            });
        }]);