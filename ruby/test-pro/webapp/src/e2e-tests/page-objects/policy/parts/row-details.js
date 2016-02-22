var RowDetailBasic = require('../../../controls/grid/row-detail-basic.js');

var rowDetails = function () {
    this.countSignatures = function(){
        return this._signatures.count();
    };
    this.countSensors = function(){
        return this._sensors.count()
    };
};

rowDetails.prototype = Object.create(RowDetailBasic.prototype, {
    _signatures: { get: function () {
        return element(by.css('.rowDetailContent')).$$('.list-group').get(0).$$('.list-group-item.search-list-item');
    }},
    _sensors: { get: function () {
        return element(by.css('.rowDetailContent')).$$('.list-group').get(1).$$('.list-group-item.search-list-item');
    }}

});

module.exports = {
    details: new rowDetails()
};