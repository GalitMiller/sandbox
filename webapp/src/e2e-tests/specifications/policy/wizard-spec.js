var PolicyWizardSpecification = function (wizard) {
    this._wizard = wizard;

    this.checkValuesEntered = function(name, desc, type, btnLbl){
        expect(this._wizard.getEnteredName()).toBe(name);

        if (desc !== null) {
            expect(this._wizard.getEnteredSecondField()).toBe(desc);
        } else {
            expect(this._wizard.getEnteredSecondField()).not.toBe('');
        }

        if (type !== null) {
            expect(this._wizard.getSelectedType()).toBe(type);
        } else {
            expect(this._wizard.getSelectedType()).not.toBe('');
        }

        expect(this._wizard.getSubmitBtnLabel()).toBe(btnLbl);
    };

    this.checkIsValid = function(isValid){
        if (isValid) {
            expect(this._wizard.checkNameHasError()).toBeFalsy();
            expect(this._wizard.checkSecondFieldHasError()).toBeFalsy();
            expect(this._wizard.checkSelectTypeHasError()).toBeFalsy();
        } else {
            expect(this._wizard.checkNameHasError()).toBeTruthy();
            expect(this._wizard.checkSecondFieldHasError()).toBeTruthy();
            expect(this._wizard.checkSelectTypeHasError()).toBeTruthy();
        }
    };

};

module.exports = PolicyWizardSpecification;