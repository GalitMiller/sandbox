var config = require('../common/config.js');
var utils = require('../common/utilities.js');

var BasePage = function(gridUrl, wizardUrl) {
    this.gridUrl = gridUrl;
    this.wizardUrl = wizardUrl;
};

BasePage.prototype = Object.create({}, {
    _navigation: { get: function () {
        return element(by.css('.main-navigation'));
    }},
    navToGrid: { value: function () {
        this.navToAngularPage(this.gridUrl);
    }},
    navToWizard: { value: function () {
        this.navToAngularPage(this.wizardUrl);
    }},
    isGridPageDisplayed: { get: function () {
        var deferred = protractor.promise.defer();
        var _this = this;
        browser.getCurrentUrl().then(function (currentURL) {
            deferred.fulfill(currentURL.endsWith(_this.gridUrl));
        });
        return deferred.promise;
    }},
    isWizardPageDisplayed: { get: function () {
        var deferred = protractor.promise.defer();
        var _this = this;
        browser.getCurrentUrl().then(function (currentURL) {
            deferred.fulfill(currentURL.endsWith(_this.wizardUrl));
        });
        return deferred.promise;
    }},
    navToAngularPage: { value: function (url) {
        browser.baseUrl = config.baseUrl;
        browser.get(url);
        browser.waitForAngular();
        var _this = this;
        browser.driver.wait(function(){
            return _this._navigation.isPresent();
        }, 5000).then(
            function(){
                console.log('-----Angular Page Loaded-----');
            },
            function(){
                console.log('-----Loading Angular Page Takes Too Long, Refreshing-----');
                browser.driver.navigate().refresh();
                browser.waitForAngular();
            }
        );
    }}
});

module.exports = BasePage;
