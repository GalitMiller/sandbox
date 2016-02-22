var SignatureCategoryWizardSpecification = function (wizard) {
    this._wizard = wizard;

    this.checkValuesEntered = function(name, desc, btnLbl){
        expect(this._wizard.getEnteredName()).toBe(name);

        if (desc !== null) {
            expect(this._wizard.getEnteredSecondField()).toBe(desc);
        } else {
            expect(this._wizard.getEnteredSecondField()).not.toBe('');
        }

        expect(this._wizard.getSubmitBtnLabel()).toBe(btnLbl);
    };

    this.checkIsValid = function(isValid){
        if (isValid) {
            expect(this._wizard.checkNameHasError()).toBeFalsy();
            expect(this._wizard.checkSecondFieldHasError()).toBeFalsy();
        } else {
            expect(this._wizard.checkNameHasError()).toBeTruthy();
            expect(this._wizard.checkSecondFieldHasError()).toBeTruthy();
        }
    };

};

module.exports = SignatureCategoryWizardSpecification;