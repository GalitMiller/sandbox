var RowDetailBasic = require('../../../controls/grid/row-detail-basic.js');
var ModalBasic = require('../../../controls/modal-basic.js');

var rowDetails = function () {
    this.importSignaturesModal = new ModalBasic('Import Signatures');
    this.addNewSignatureModal = new ModalBasic('Create New Signature');

    this.openImportSignaturesModal = function(){
        return this._importSignaturesBtn.click();
    };

    this.openNewSignatureModal = function(){
        return this._addNewSignatureBtn.click();
    };

    this.countSignatures = function(){
        return this._signatures.count();
    };
};

rowDetails.prototype = Object.create(RowDetailBasic.prototype, {
    _signatures: { get: function () {
        return element(by.css('.rowDetailContent')).$$('.list-group').get(0).$$('.list-group-item.search-list-item');
    }},
    _addNewSignatureBtn : { get: function () {
        return element(by.buttonText('Add New Signature'));
    }},
    _importSignaturesBtn : { get: function () {
        return element(by.buttonText('Import Signatures'));
    }}
});

module.exports = {
    details: new rowDetails()
};