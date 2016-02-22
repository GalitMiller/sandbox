var utils = require('../common/utilities.js');

var WizardBasic = function(nameFieldSelect, secondFieldSelect) {
    this._nameFieldSelect_ = nameFieldSelect;
    this._secondFieldSelect_ = secondFieldSelect;

    this.buttonNames = {
        create: 'Create',
        save: 'Save',
        clone: 'Clone'
    };
};

WizardBasic.prototype = Object.create({}, {
    ///NAME///
    _nameField: { get: function () {
        return element(this._nameFieldSelect_);
    }},
    setName: { value: function (txt) {
        return this._nameField.sendKeys(txt);
    }},
    getEnteredName: { value: function () {
        return this._nameField.getAttribute('value');
    }},
    clearName: { value: function () {
        return this._nameField.clear();
    }},
    checkNameHasError: { value: function () {
        return utils.checkHasError(this._nameField);
    }},

    ///DESCRIPTION///
    _secondField: { get: function () {
        return element(this._secondFieldSelect_);
    }},
    setSecondField: { value: function (txt) {
        return this._secondField.sendKeys(txt);
    }},
    getEnteredSecondField: { value: function () {
        return this._secondField.getAttribute('value');
    }},
    clearSecondField: { value: function () {
        return this._secondField.clear();
    }},
    checkSecondFieldHasError: { value: function () {
        return utils.checkHasError(this._secondField);
    }},

    ///SAVE///
    _submitButton: { get: function () {
        return element(by.id('saveBtn'));
    }},
    getSubmitBtnLabel: { value: function () {
        return this._submitButton.getAttribute('value');
    }},
    save: { value: function () {
        return this._submitButton.click();
    }},

    ///CANCEL///
    _cancelButton: { get: function () {
        return element(by.buttonText('Cancel'));
    }},
    cancel: { value: function () {
        return this._cancelButton.click();
    }}
});

module.exports = WizardBasic;