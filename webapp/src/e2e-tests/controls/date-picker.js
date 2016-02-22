var BasicSelect = require('./select/basic-select.js');

var DatePicker = function(ctrlSelector) {
    BasicSelect.call(this, ctrlSelector);

    this.selectDay = function(name){
        var deferred = protractor.promise.defer();
        var _this = this;
        this._selected.click().then(function(){
            _this.getOption(name).then(function(foundOption){
                foundOption.click().then(function(){
                    _this._selected.click().then(function(){
                        deferred.fulfill();
                    });
                });
            });
        });
        return deferred.promise;
    };

};

DatePicker.prototype = Object.create(BasicSelect.prototype, {
    _options: {get: function () {
        return element(this._ctrlSelector_).$$('tbody').get(0).$$('button');
    }},
    _selected: {get: function () {
        return element(this._ctrlSelector_).$('.date-picker-input');
    }},
    getSelectedOptionTxt: { value: function () {
        return this._selected.getAttribute('value');
    }}
});

module.exports = DatePicker;