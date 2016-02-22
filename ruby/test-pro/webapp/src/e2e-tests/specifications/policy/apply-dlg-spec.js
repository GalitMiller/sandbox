var PolicyApplyDialogSpecification = function (dialog) {
    this._dialog = dialog;

    this.checkFirstStep = function(isCustomEnabled){
        expect(this._dialog.isSensorSelectionDisplayed()).toBeTruthy();

        if (isCustomEnabled) {
            expect(this._dialog.isCustomSensorSelectionAvailable()).toBeTruthy();
        } else {
            expect(this._dialog.isCustomSensorSelectionAvailable()).toBeFalsy();
        }

        expect(this._dialog.isPolicySelectionDisplayed()).toBeFalsy();
    };

    this.checkSecondStep = function(){
        expect(this._dialog.isSensorSelectionDisplayed()).toBeFalsy();
        expect(this._dialog.isPolicySelectionDisplayed()).toBeTruthy();
        expect(this._dialog.isPolicySelectionAvailable()).toBeTruthy();
    };

};

module.exports = PolicyApplyDialogSpecification;