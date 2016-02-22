angular.module('bricata.ui.policy')
    .factory('SignaturePreviewItem', ['$resource', 'BricataUris',
        function($resource, BricataUris){
            return $resource(BricataUris.sendSignatureForPreview, {}, {
                singlePreview: {method: 'POST'}
            });
        }]);
