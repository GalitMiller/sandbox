var utils = require('../../common/utilities.js');
var BasicSelect = require('./basic-select.js');

var DefaultSelect = function(ctrlSelector, optionsSelector) {
    BasicSelect.call(this, ctrlSelector);
    this._optionsSelector_ = optionsSelector;

    this.selectOptionByLabel = function(name){
        var deferred = protractor.promise.defer();
        this.getOption(name).then(function(foundOption){
            foundOption.click().then(function(){
                deferred.fulfill();
            });
        });
        return deferred.promise;
    };

    this.hasError = function(){
        return utils.checkHasError(this._ctrl);
    };
};

DefaultSelect.prototype = Object.create(BasicSelect.prototype, {
    _options: { get: function () {
        return element.all(this._optionsSelector_);
    }},
    _selected: {get: function () {
        return element(this._ctrlSelector_).$('option:checked');
    }}
});

module.exports = DefaultSelect;