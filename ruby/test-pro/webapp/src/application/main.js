var $routeProviderReference, $gridConfiguration;
window.BPACApp = angular.module("BPACApp",
    ["ngRoute", "jm.i18next", "ngScrollable", "ngCookies", "bricata.uicore", "bricata.bpac"])
    .config(['$compileProvider', function ($compileProvider) {
        // disable debug info - performance improvement, run "angular.reloadWithDebugInfo()" in console to enable back
        $compileProvider.debugInfoEnabled(false);
    }])
    .config(function($httpProvider) {
        $httpProvider.interceptors.push(function ($q) {
            return {
                'request': function (config) {
                    config.url = config.url.replace(/%2F/gi, '/');
                    return config || $q.when(config);
                }
            };
        });
    })
    .config(['$routeProvider', function($routeProvider){
        //this should save reference to route, so we can config it later
        $routeProviderReference = $routeProvider;
    }])
    .config(['GridConfigurationProvider', function(GridConfigurationProvider){
        $gridConfiguration = GridConfigurationProvider;
    }])
    .config(['$tooltipProvider', function($tooltipProvider){
        $tooltipProvider.setTriggers({
            'mouseenter': 'mouseleave',
            'click': 'click',
            'focus': 'blur',
            'validationfailed': 'validationpassed'
        });
    }]).controller("MainController",
    ["$scope", "$i18next", "$interval", "UserInfoService", "CommonNavigationService",
        "ConfigurationService", "ReportingService",
        function($scope, $i18next, $interval, UserInfoService, CommonNavigationService,
                 ConfigurationService, ReportingService) {

            $scope.translationLoaded = false;
            $scope.userInfoLoaded = true;
            $scope.configurationLoaded = false;

            ReportingService.setUpGridReportViews($gridConfiguration);
            CommonNavigationService.setupNavigation($routeProviderReference);

            var l10nLoadedCheck = $interval(function() {
                if ($i18next('mainTitle') !== 'mainTitle') {
                    $interval.cancel(l10nLoadedCheck);

                    $scope.translationLoaded = true;
                    document.title = $i18next('mainTitle');
                }
            }, 50);

            /* this doesn't work in 5-10% of cases
            $scope.$on('i18nextLanguageChange', function () {
                $scope.translationLoaded = true;
                document.title = $i18next('mainTitle');
            });*/

            UserInfoService.getUserInfo().then(function success(data) {
                $scope.userData = data;
                UserInfoService.saveLoadedUserInfo(data);
                $scope.userInfoLoaded = true;
            }, function error() {
                //CommonNavigationService.navigateToLoginPage();
                $scope.userInfoLoaded = true;
            });

            ConfigurationService.loadConfiguration().then(function(data) {
                ConfigurationService.setConfiguration(data);
                $scope.configurationLoaded = true;
            });
    }]);

var LOCALIZATION_NAME_SPACE = "bundle";

angular.module('jm.i18next').config(['$i18nextProvider', function ($i18nextProvider) {
    $i18nextProvider.options = {
        ns: {
            namespaces: [LOCALIZATION_NAME_SPACE],
            defaultNs: LOCALIZATION_NAME_SPACE
        },
        resGetPath: "i18n/__ns_____lng__.json",
        fallbackLng: "en",
        lng: "en"
    };
}]);