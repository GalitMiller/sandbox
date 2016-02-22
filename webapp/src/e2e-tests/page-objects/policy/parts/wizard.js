var DefaultSelect = require('../../../controls/select/default-select.js');
var WizardBasic = require('../../../controls/wizard-basic.js');

var policyWizard = function () {
    WizardBasic.call(this, by.id('policyName'), by.id('policyDescription'));

    this._typeSelect = new DefaultSelect(by.id('policyType'),
        by.options('(key.i18nLabel | i18next) for key in ::policyTypeList'));

    this.getSelectedType = function(){
        return this._typeSelect.getSelectedOptionTxt();
    };

    this.selectType = function(name){
        return this._typeSelect.selectOptionByLabel(name);
    };

    this.checkSelectTypeHasError = function(){
        return this._typeSelect.hasError();
    };
};

policyWizard.prototype = Object.create(WizardBasic.prototype, {});

module.exports = {
    wizard: new policyWizard()
};