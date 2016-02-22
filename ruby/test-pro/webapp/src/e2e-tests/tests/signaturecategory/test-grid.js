var categories = require('../../page-objects/signature-category/page.js');

var GridSpecification = require('../../specifications/grid-spec.js');
var SignatureCategoryWizardSpecification = require('../../specifications/signature-category/wizard-spec.js');

var gridSpec = new GridSpecification(categories.page.grid, categories.page.gridFilter);
var wizardSpec = new SignatureCategoryWizardSpecification(categories.page.wizard);

describe('signature categories grid', function() {
    beforeEach(function() {
        categories.page.navToGrid();
    });

    it('check grid columns appearance', function() {
        gridSpec.checkAllColumns();
    });

    it('check grid columns sorting', function() {

        gridSpec.checkColumnIsNotSorted(2);
        categories.page.grid.clickColumn(2).then(function(){
            gridSpec.checkColumnSorted(2);
        });

        categories.page.grid.clickColumn(0).then(function(){
            gridSpec.checkColumnIsNotSorted(0);
        });

        categories.page.grid.clickColumn(4).then(function(){
            gridSpec.checkColumnIsNotSorted(4);
        });
    });

    it('check grid rows presence', function() {
        gridSpec.checkRowsPresent();
    });

    it('check signature categories grid details can be displayed and closed', function() {
        gridSpec.checkDetailsDisplayedForRow(0, false);

        categories.page.grid.openDetailsForRow(0).then(function(){
            gridSpec.checkDetailsDisplayedForRow(0, true);

            categories.page.grid.collapseRowDetail().then(function() {
                gridSpec.checkDetailsDisplayedForRow(0, false);
            });
        });
    });

    it('check bulk delete button enables/disables and opens modal', function() {
        gridSpec.checkIsBulkDeleteAllowed(false);

        categories.page.grid.findRowWithAction(categories.page.grid.actions.delete).then(function(deletableRowNum){
            if (deletableRowNum > -1) {
                categories.page.grid.clickRowCheckBox(deletableRowNum).then(function(){
                    gridSpec.checkIsBulkDeleteAllowed(true);
                    gridSpec.checkModalDisplayed(categories.page.deleteModal, false);

                    categories.page.grid.clickBulkDelete().then(function() {
                        gridSpec.checkModalDisplayed(categories.page.deleteModal, true);

                        categories.page.deleteModal.cancelDialog().then(function() {
                            gridSpec.checkModalDisplayed(categories.page.deleteModal, false);

                            categories.page.grid.clickRowCheckBox(deletableRowNum).then(function(){
                                gridSpec.checkIsBulkDeleteAllowed(false);
                            });
                        });
                    });
                });
            }
        });
    });

    it('check row delete button works', function() {
        gridSpec.checkModalDisplayed(categories.page.deleteModal, false);

        categories.page.grid.findRowWithAction(categories.page.grid.actions.delete).then(function(deletableRowNum){
            if (deletableRowNum > -1) {
                categories.page.grid.invokeAction(deletableRowNum, categories.page.grid.actions.delete).
                    then(function(){
                        gridSpec.checkModalDisplayed(categories.page.deleteModal, true);

                        categories.page.deleteModal.cancelDialog().then(function() {
                            gridSpec.checkModalDisplayed(categories.page.deleteModal, false);
                        });
                    });
            }
        });
    });

    it('check row edit button works', function() {
        var categoryName;
        categories.page.grid.readCellValue(0, categories.page.grid.columnsMeta[1].label).then(function (value) {
            categoryName = value;
            categories.page.grid.invokeAction(0, categories.page.grid.actions.edit)
                .then(function(){
                    expect(categories.page.isWizardPageDisplayed).toBeTruthy();

                    wizardSpec.checkValuesEntered(categoryName, null, categories.page.wizard.buttonNames.save);
                    wizardSpec.checkIsValid(true);

                    categories.page.wizard.cancel().then(function(){
                        expect(categories.page.isGridPageDisplayed).toBeTruthy();
                    });
            });
        });
    });

    it('check signature categories grid details appearance', function() {
        var signatureDescription;
        categories.page.grid.readCellValue(0, categories.page.grid.columnsMeta[2].label).then(function (value) {
            signatureDescription = value;
            categories.page.grid.openDetailsForRow(0).then(function(){
                gridSpec.checkDetailsDisplayedForRow(0, true);
                expect(categories.page.rowDetails.countSignatures()).toBeGreaterThan(0);

                categories.page.rowDetails.openNewSignatureModal().then(function () {
                    gridSpec.checkModalDisplayed(categories.page.rowDetails.addNewSignatureModal, true);
                });
                categories.page.rowDetails.addNewSignatureModal.cancelDialog().then(function () {
                    gridSpec.checkModalDisplayed(categories.page.rowDetails.addNewSignatureModal, false);
                });
                categories.page.rowDetails.openImportSignaturesModal().then(function(){
                    gridSpec.checkModalDisplayed(categories.page.rowDetails.importSignaturesModal, true);
                });
                categories.page.rowDetails.importSignaturesModal.cancelDialog().then(function() {
                    gridSpec.checkModalDisplayed(categories.page.rowDetails.importSignaturesModal, false);
                });

                categories.page.rowDetails.close().then(function(){
                    gridSpec.checkDetailsDisplayedForRow(0, false);
                });
            });
        });
    });

});