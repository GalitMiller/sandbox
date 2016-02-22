var BasicSelect = require('./basic-select.js');

var CustomSelect = function(ctrlSelector) {
    BasicSelect.call(this, ctrlSelector);

    this.selectOptionByLabel = function(name){
        var deferred = protractor.promise.defer();
        var _this = this;
        this._selected.click().then(function(){
            _this.getOption(name).then(function(foundOption){
                foundOption.click().then(function(){
                    deferred.fulfill();
                });
            });
        });
        return deferred.promise;
    };
};

CustomSelect.prototype = Object.create(BasicSelect.prototype, {
    _options: { get: function () {
        return element(this._ctrlSelector_).$$('.select-ctrl-dropdown').get(0).$$('.truncated');
    }},
    _selected: {get: function () {
        return element(this._ctrlSelector_).$('.select-ctrl');
    }}
});

module.exports = CustomSelect;