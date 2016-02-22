var RowDetailBasic = function() {};

RowDetailBasic.prototype = Object.create({}, {
    _description: { get: function () {
        return element(by.css('.rowDetailContent')).$$('.selected-row-description').get(0);
    }},
    _collapseBtn: { get: function () {
        return element(by.css('.rowDetailContent')).$$('.hideDetails').get(0);
    }},
    getDescriptionTxt: { value: function () {
        return this._description.getText();
    }},
    close: { value: function () {
        return this._collapseBtn.click();
    }}
});

module.exports = RowDetailBasic;