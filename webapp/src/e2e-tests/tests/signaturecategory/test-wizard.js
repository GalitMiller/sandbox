var signatureCategory = require('../../page-objects/signature-category/page.js');

var SignatureCategoryWizardSpecification = require('../../specifications/signature-category/wizard-spec.js');

var wizardSpec = new SignatureCategoryWizardSpecification(signatureCategory.page.wizard);

describe('signature category wizard', function() {
    beforeEach(function () {
        signatureCategory.page.navToWizard();
    });

    it('check signature category wizard appearance', function () {
        wizardSpec.checkValuesEntered('', '', signatureCategory.page.wizard.buttonNames.create);
        wizardSpec.checkIsValid(true);
    });

    it('errors messages appearance and disappear', function () {
        signatureCategory.page.wizard.setName('');
        signatureCategory.page.wizard.setSecondField('a');

        signatureCategory.page.wizard._submitButton.click().then(function(){
            wizardSpec.checkIsValid(false);
        });

        signatureCategory.page.wizard.setName('test');
        signatureCategory.page.wizard.setSecondField('test');

        wizardSpec.checkValuesEntered('test', 'atest', signatureCategory.page.wizard.buttonNames.create);
        wizardSpec.checkIsValid(true);
    });

    it('cancel button navigate to Category grid page', function () {
        signatureCategory.page.wizard._cancelButton.click().then(function(){
            expect(signatureCategory.page.isGridPageDisplayed).toBeTruthy();
        });
    });

});
