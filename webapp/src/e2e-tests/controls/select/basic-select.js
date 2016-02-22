var BasicSelect = function(ctrlSelector) {
    this._ctrlSelector_ = ctrlSelector;
};

BasicSelect.prototype = Object.create({}, {
    _options: { get: function () {
        return null;
    }},
    _selected: {get: function () {
        return null;
    }},
    _ctrl: {get: function () {
        return element(this._ctrlSelector_);
    }},
    getSelectedOptionTxt: { value: function () {
        return this._selected.getText();
    }},
    getOption: { value: function (optionName) {
        var deferred = protractor.promise.defer();
        var pendingPromisesSize = 0;
        var totalCount;
        var optionMatch;
        var _this = this;

        this._options.count().then(function(optionsNum){
            totalCount = optionsNum;

            _this._options.each(function (option) {
                option.getText().then(function (optionText) {
                    if (optionText === optionName) {
                        optionMatch = option;
                    }

                    pendingPromisesSize++;

                    if (totalCount === pendingPromisesSize) {
                        deferred.fulfill(optionMatch);
                    }
                });
            });
        });

        return deferred.promise;
    }}
});

module.exports = BasicSelect;