var policy = require('../../page-objects/policy/page.js');

var PolicyWizardSpecification = require('../../specifications/policy/wizard-spec.js');

var wizardSpec = new PolicyWizardSpecification(policy.page.wizard);

describe('policies wizard', function() {
    beforeEach(function () {
        policy.page.navToWizard();
    });

    it('check policy wizard appearance', function () {

        wizardSpec.checkValuesEntered('', '', 'Select Policy Type', policy.page.wizard.buttonNames.create);
        wizardSpec.checkIsValid(true);

        policy.page.wizard.selectType('Select Policy Type').then(function(){
            policy.page.wizard.setName('');
            policy.page.wizard.setSecondField('a');

            wizardSpec.checkIsValid(false);
        });

        policy.page.wizard.clearName();
        policy.page.wizard.clearSecondField();

        policy.page.wizard.selectType('ProAccel Categories').then(function() {
            policy.page.wizard.setName('test');
            policy.page.wizard.setSecondField('test');

            wizardSpec.checkValuesEntered('test', 'test', 'ProAccel Categories', policy.page.wizard.buttonNames.create);
            wizardSpec.checkIsValid(true);
        });
    });
});
