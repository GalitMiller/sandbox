var WizardBasic = require('../../../controls/wizard-basic.js');

var categoryWizard = function () {
    WizardBasic.call(this, by.id('signatureCategoryName'), by.id('signatureCategoryDescription'));
};

categoryWizard.prototype = Object.create(WizardBasic.prototype, {});

module.exports = {
    wizard: new categoryWizard()
};