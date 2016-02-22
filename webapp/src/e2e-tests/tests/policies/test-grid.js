var policy = require('../../page-objects/policy/page.js');

var GridSpecification = require('../../specifications/grid-spec.js');
var PolicyApplyDialogSpecification = require('../../specifications/policy/apply-dlg-spec.js');
var PolicyWizardSpecification = require('../../specifications/policy/wizard-spec.js');

var gridSpec = new GridSpecification(policy.page.grid, policy.page.gridFilter);
var applyDlgSpec = new PolicyApplyDialogSpecification(policy.page.applyModal);
var wizardSpec = new PolicyWizardSpecification(policy.page.wizard);

describe('policies grid', function() {
    beforeEach(function() {
        policy.page.navToGrid();
    });

    it('check grid columns appearance', function() {

        gridSpec.checkAllColumns();

    });

    it('check grid columns sorting', function() {

        gridSpec.checkColumnIsNotSorted(2);
        policy.page.grid.clickColumn(2).then(function(){
            gridSpec.checkColumnSorted(2);
        });

        policy.page.grid.clickColumn(0).then(function(){
            gridSpec.checkColumnIsNotSorted(0);
        });

        policy.page.grid.clickColumn(7).then(function(){
            gridSpec.checkColumnIsNotSorted(7);
        });
    });

    it('check grid rows presence', function() {
        gridSpec.checkRowsPresent();
    });

    it('check policy grid details can be displayed and closed', function() {
        gridSpec.checkDetailsDisplayedForRow(0, false);

        policy.page.grid.openDetailsForRow(0).then(function(){
            gridSpec.checkDetailsDisplayedForRow(0, true);

            policy.page.grid.collapseRowDetail().then(function() {
                gridSpec.checkDetailsDisplayedForRow(0, false);
            });
        });
    });

    it('check bulk delete button enables/disables and opens modal', function() {
        gridSpec.checkIsBulkDeleteAllowed(false);

        policy.page.grid.findRowWithAction(policy.page.grid.actions.delete).then(function(deletableRowNum){
            if (deletableRowNum > -1) {
                policy.page.grid.clickRowCheckBox(deletableRowNum).then(function(){
                    gridSpec.checkIsBulkDeleteAllowed(true);
                    gridSpec.checkModalDisplayed(policy.page.deleteModal, false);

                    policy.page.grid.clickBulkDelete().then(function() {
                        gridSpec.checkModalDisplayed(policy.page.deleteModal, true);

                        policy.page.deleteModal.cancelDialog().then(function() {
                            gridSpec.checkModalDisplayed(policy.page.deleteModal, false);

                            policy.page.grid.clickRowCheckBox(deletableRowNum).then(function(){
                                gridSpec.checkIsBulkDeleteAllowed(false);
                            });
                        });
                    });
                });
            }
        });
    });

    it('check row delete button works', function() {
        gridSpec.checkModalDisplayed(policy.page.deleteModal, false);

        policy.page.grid.findRowWithAction(policy.page.grid.actions.delete).then(function(deletableRowNum){
            if (deletableRowNum > -1) {
                policy.page.grid.invokeAction(deletableRowNum, policy.page.grid.actions.delete).then(function(){
                    gridSpec.checkModalDisplayed(policy.page.deleteModal, true);

                    policy.page.deleteModal.cancelDialog().then(function() {
                        gridSpec.checkModalDisplayed(policy.page.deleteModal, false);
                    });
                });
            }
        });
    });

    it('check row edit button works', function() {
        var policyName;
        policy.page.grid.readCellValue(0, policy.page.grid.columnsMeta[1].label).then(function (value) {
            policyName = value;

            policy.page.grid.invokeAction(0, policy.page.grid.actions.edit).then(function(){
                expect(policy.page.isWizardPageDisplayed).toBeTruthy();

                wizardSpec.checkValuesEntered(policyName, null, null, policy.page.wizard.buttonNames.save);
                wizardSpec.checkIsValid(true);

                policy.page.wizard.cancel().then(function(){
                    expect(policy.page.isGridPageDisplayed).toBeTruthy();
                });
            });
        });
    });

    it('check row clone button works', function() {
        var policyName;
        policy.page.grid.readCellValue(0, policy.page.grid.columnsMeta[1].label).then(function (value) {
            policyName = value;

            policy.page.grid.invokeAction(0, policy.page.grid.actions.clone).then(function(){
                expect(policy.page.isWizardPageDisplayed).toBeTruthy();

                wizardSpec.checkValuesEntered('Copy of ' + policyName, null, null,
                    policy.page.wizard.buttonNames.clone);
                wizardSpec.checkIsValid(true);

                policy.page.wizard.cancel().then(function(){
                    expect(policy.page.isGridPageDisplayed).toBeTruthy();
                });
            });
        });
    });

    it('check policy grid details appearance', function() {
        var policyDescription;
        policy.page.grid.readCellValue(0, 'Description').then(function (value) {
            policyDescription = value;
            policy.page.grid.openDetailsForRow(0).then(function(){
                gridSpec.checkDetailsDisplayedForRow(0, true);
                gridSpec.checkRowDetailsListsAreNotEmpty([
                    policy.page.rowDetails.countSignatures(),
                    policy.page.rowDetails.countSensors()
                ]);

                policy.page.rowDetails.close().then(function(){
                    gridSpec.checkDetailsDisplayedForRow(0, false);
                });
            });
        });
    });

    it('check grid header Create Policy button works', function() {
        expect(policy.page.isGridPageDisplayed).toBeTruthy();

        policy.page.header.invokeHeaderAction(policy.page.header.actions.create);
        expect(policy.page.isWizardPageDisplayed).toBeTruthy();
    });

    it('check grid header Apply Policy button works', function() {
        gridSpec.checkModalDisplayed(policy.page.applyModal, false);

        policy.page.header.invokeHeaderAction(policy.page.header.actions.apply);
        gridSpec.checkModalDisplayed(policy.page.applyModal, true);

        policy.page.applyModal.cancelDialog();
        gridSpec.checkModalDisplayed(policy.page.applyModal, false);
    });

    it('check Apply Policy modal appearance', function() {
        policy.page.header.invokeHeaderAction(policy.page.header.actions.apply);

        gridSpec.checkModalDisplayed(policy.page.applyModal, true);
        applyDlgSpec.checkFirstStep(true);

        policy.page.applyModal.selectAllApply();
        applyDlgSpec.checkFirstStep(false);

        policy.page.applyModal.selectCustomApply();
        applyDlgSpec.checkFirstStep(true);

        policy.page.applyModal.selectAllApply();
        policy.page.applyModal.navToSecondStep();
        applyDlgSpec.checkSecondStep(true);

        policy.page.applyModal.navToFirstStep();
        applyDlgSpec.checkFirstStep(false);
    });

    it('check grid filter value remains during navigation', function() {
        gridSpec.checkFilterValues('', 'Anyone', '', '');

        policy.page.gridFilter.setSearchFilter('test');
        policy.page.gridFilter.setFilterOption('Administrator');

        policy.page.gridFilter.selectStartDate('01');
        var selectedStartDate;
        policy.page.gridFilter.getStartDateValue().then(function(value){
            selectedStartDate = value;
        });

        policy.page.gridFilter.selectEndDate('02');
        var selectedEndDate;
        policy.page.gridFilter.getEndDateValue().then(function(value){
            selectedEndDate = value;
        });

        policy.page.header.invokeHeaderAction(policy.page.header.actions.create);
        expect(policy.page.isWizardPageDisplayed).toBeTruthy();

        policy.page.wizard.cancel().then(function(){
            expect(policy.page.isGridPageDisplayed).toBeTruthy();

            gridSpec.checkFilterValues('test', 'Administrator', selectedStartDate, selectedEndDate);
        });
    });

});