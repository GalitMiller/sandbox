var ModalBasic = function(title) {
    this._title_ = title;
};

ModalBasic.prototype = Object.create({}, {
    _allModals: { get: function () {
        return element.all(by.css('.modal-content'));
    }},
    _cancelButton: { get: function () {
        return element(by.css('.modal-content')).$$('.glyphicon-remove');
    }},
    cancelDialog: { value: function () {
        return this._cancelButton.click();
    }},
    isModalDisplayed: { value: function () {
        var deferred = protractor.promise.defer();
        var _this = this;
        this._allModals.count().then(function (countValue) {
            if (countValue > 0) {
                _this._allModals.get(0).$$('.modal-title').get(0).getText().then(function(modalTitle){
                    deferred.fulfill(_this._title_ === modalTitle);
                });
            } else {
                deferred.fulfill(false);
            }
        });
        return deferred.promise;
    }}
});

module.exports = ModalBasic;