var config = require('../common/config.js');

var userNameField = $('.required.email');
var userPswdField = $('.required.password');
var logMeInButton = $('.login-button.login-default');

describe('login to app', function() {
    it('non-angular page so ignore sync and active wait to load', function() {
        if (config.login) {
            //this is not angular page, so disable protractor check for angular
            browser.ignoreSynchronization = true;

            //deleting cookies to force login page load without delay
            browser.driver.manage().deleteAllCookies();

            browser.get(config.login.pageUrl).then(function(){
                //force browser to wait for login page to load
                expect(userNameField.isPresent()).toBeTruthy();
                expect(userPswdField.isPresent()).toBeTruthy();
                expect(logMeInButton.isPresent()).toBeTruthy();
            });
        }
    });

    it('should fill user and password and logins', function() {
        if (config.login) {
            userNameField.sendKeys(config.login.user);
            userPswdField.sendKeys(config.login.password);
            logMeInButton.click().then(function(){
                //wait for the session to be set in browser
                browser.sleep(5000);
            });
        }
    });

    it('restores ignore sync when switching back to angular pages', function() {
        if (config.login) {
            //switch back to angular dependencies in protractor
            browser.ignoreSynchronization = false;
        }
    });
});
