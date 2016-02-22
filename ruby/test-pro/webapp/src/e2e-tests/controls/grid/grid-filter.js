var CustomSelect = require('./../select/custom-select.js');
var DatePicker = require('../date-picker.js');

var gridFilter = function () {
    this._optionFilter = new CustomSelect(by.model('selectedFilters.valueFilterVal'));
    this._startDate  = new DatePicker(by.id('dateFromPicker'));
    this._endDate = new DatePicker(by.id('dateToPicker'));

    this.setSearchFilter = function(value){
        return this._searchBox.sendKeys(value);
    };

    this.getSearchFilter = function(action){
        return this._searchBox.getAttribute('value');
    };

    this.getCurrentFilterOption = function(){
        return this._optionFilter.getSelectedOptionTxt();
    };

    this.setFilterOption = function(value){
        return this._optionFilter.selectOptionByLabel(value);
    };

    this.selectStartDate = function(dayNum){
        return this._startDate.selectDay(dayNum);
    };

    this.getStartDateValue = function(){
        return this._startDate.getSelectedOptionTxt();
    };

    this.selectEndDate = function(dayNum){
        return this._endDate.selectDay(dayNum);
    };

    this.getEndDateValue = function(){
        return this._endDate.getSelectedOptionTxt();
    };
};

gridFilter.prototype = Object.create({}, {
    _searchBox: { get: function () {
        return element(by.model('selectedFilters.searchFilterVal'));
    }}
});

module.exports = {
    filter: new gridFilter()
};