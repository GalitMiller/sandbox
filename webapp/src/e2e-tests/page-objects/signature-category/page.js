var config = require('../../common/config.js');
var BasePage = require('../base-page.js');

var GridPage = require('../../controls/grid/grid.js');
var ModalBasic = require('../../controls/modal-basic.js');
var signatureCategoriesWizard = require('./parts/wizard.js');
var signatureCategoriesDetails = require('./parts/row-details.js');
var signatureCategoriesGridFilter = require('../../controls/grid/grid-filter.js');

var categoriesPage = function () {
    BasePage.call(this, config.categoryUrls.grid, config.categoryUrls.wizard);

    this.grid = new GridPage();
    this.gridFilter = signatureCategoriesGridFilter.filter;
    this.deleteModal = new ModalBasic('Delete Signature category');
    this.wizard = signatureCategoriesWizard.wizard;
    this.rowDetails = signatureCategoriesDetails.details;

    this.grid.setColumnsMetaInfo([
        {label: '', isCheck: true},
        {label: 'Category Name', isDefaultSort: true},
        {label: 'Description'},
        {label: 'Signatures'},
        {label: 'Actions', isActionCol: true}
    ]);
};

categoriesPage.prototype = Object.create(BasePage.prototype, {});

module.exports = {
    page: new categoriesPage()
};
