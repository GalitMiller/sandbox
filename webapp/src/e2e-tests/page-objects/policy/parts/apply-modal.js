var ModalBasic = require('../../../controls/modal-basic.js');

var applyPolicyDialog = function () {
    ModalBasic.call(this, 'Apply Policy');

    this.isSensorSelectionDisplayed = function(){
        var deferred = protractor.promise.defer();

        this._dialogSubTitle.getText().then(function (subTitle) {
            deferred.fulfill(subTitle === 'Sensors and Interfaces');
        });

        return deferred.promise;
    };

    this.isPolicySelectionDisplayed = function(){
        var deferred = protractor.promise.defer();

        this._dialogSubTitle.getText().then(function (subTitle) {
            deferred.fulfill(subTitle === 'Policies and Actions');
        });

        return deferred.promise;
    };

    this.isCustomSensorSelectionAvailable = function(){
        return this._sensorSelectContainer.isPresent();
    };

    this.isPolicySelectionAvailable = function(){
        return this._policySelectContainer.isPresent();
    };

    this.selectAllApply = function(){
        return this._applyForOptions.get(0).click();
    };

    this.selectCustomApply = function(){
        return this._applyForOptions.get(1).click();
    };

    this.navToFirstStep = function(){
        return this._stepOptions.get(0).click();
    };

    this.navToSecondStep = function(){
        return this._stepOptions.get(1).click();
    };
};

applyPolicyDialog.prototype = Object.create(ModalBasic.prototype, {
    _dialogSubTitle: { get: function () {
        return element(by.css('.apply-dlg-subtitle'));
    }},
    _sensorSelectContainer: { get: function () {
        return element(by.css('div[sensor-select-validation]'));
    }},
    _policySelectContainer: { get: function () {
        return element(by.css('div[policy-select-validation]'));
    }},
    _applyForOptions: { get: function () {
        return element.all(by.css('input[name="applyFor"]'));
    }},
    _stepOptions: { get: function () {
        return element.all(by.css('.modal-step'));
    }}
});

module.exports = {
    dialog: new applyPolicyDialog()
};