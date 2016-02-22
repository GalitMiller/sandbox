var config = require('../../common/config.js');
var BasePage = require('../base-page.js');

var policyGridHeader = require('../../controls/grid/grid-header.js');
var GridPage = require('../../controls/grid/grid.js');
var policyGridFilter = require('../../controls/grid/grid-filter.js');
var ModalBasic = require('../../controls/modal-basic.js');
var policyWizard = require('./parts/wizard.js');
var policyDetails = require('./parts/row-details.js');
var applyPolicyDialog = require('./parts/apply-modal.js');

var policyPage = function () {
    BasePage.call(this, config.policyUrls.grid, config.policyUrls.wizard);

    this.header = policyGridHeader.header;
    this.grid = new GridPage();
    this.gridFilter = policyGridFilter.filter;
    this.deleteModal = new ModalBasic('Delete Policy');
    this.wizard = policyWizard.wizard;
    this.rowDetails = policyDetails.details;
    this.applyModal = applyPolicyDialog.dialog;

    this.grid.setColumnsMetaInfo([
        {label: '', isCheck: true},
        {label: 'Policy Name', isDefaultSort: true},
        {label: 'Description'},
        {label: 'Signatures'},
        {label: 'Last Applied By'},
        {label: 'Date Created'},
        {label: 'Created By'},
        {label: 'Actions', isActionCol: true}
    ]);
};

policyPage.prototype = Object.create(BasePage.prototype, {});

module.exports = {
    page: new policyPage()
};
