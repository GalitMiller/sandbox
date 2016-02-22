angular.module('bricata.uicore.modal')
    .service('CommonModalService', [ '$modal', '$document', '$timeout', '$window',
        function($modal, $document, $timeout, $window){
            var modalDefaults = {
                backdrop: 'static',
                keyboard: true,
                modalFade: true
            };

            this.showModal = function (customModalDefaults, customModalOptions) {
                if (!customModalDefaults) {
                    customModalDefaults = {};
                }
                return this.show(customModalDefaults, customModalOptions);
            };

            this.show = function (customModalDefaults) {
                //Create temp objects to work with since we're in a singleton service
                var tempModalDefaults = {};

                //Map angular-ui modal custom defaults to modal defaults defined in service
                angular.extend(tempModalDefaults, modalDefaults, customModalDefaults);

                return $modal.open(tempModalDefaults).result;
            };

            this.centerModal = function() {
                $timeout(function() {
                    angular.forEach($document[0].querySelectorAll(".modal"), function (modal) {
                        var modalElement = angular.element(modal);
                        var clone = modalElement.clone().css({display: 'block'});
                        modalElement.parent().append(clone);
                        var top = Math.round((clone[0].offsetHeight -
                            angular.element(clone[0].querySelector(".modal-content"))[0].offsetHeight) / 2);
                        top = top > 0 ? top : 0;
                        clone.remove();
                        angular.element(modalElement[0].querySelector(".modal-content")).css({marginTop: top+'px'});
                    }, 333, false);
                });
            };

            this.bindRepositionOnResize = function() {
                angular.element($window).on('resize', this.centerModal);
            };

            this.unbindRepositionOnResize = function() {
                angular.element($window).off('resize', this.centerModal);
            };

        }]);
