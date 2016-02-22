var gridHeader = function () {
    this.actions = {
        create: '.glyphicon.glyphicon-plus',
        import: '.glyphicon.glyphicon-import',
        export: '.glyphicon.glyphicon-export',
        apply:  '.glyphicon.glyphicon-ok'
    };

    this.invokeHeaderAction = function(action){
        return this._gridHeader.$$(action).click();
    };
};

gridHeader.prototype = Object.create({}, {
    _gridHeader: { get: function () {
        return element(by.css('.grid-top-header'));
    }}
});

module.exports = {
    header: new gridHeader()
};