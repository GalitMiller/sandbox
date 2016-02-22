var utils = require('../../common/utilities.js');

var GridPage = function () {
    this.columnsMeta = [];
    this.actions = {
        clone: '.glyphicon.glyphicon-duplicate.rowAction',
        edit: '.glyphicon.glyphicon-pencil.rowAction',
        delete: '.glyphicon.glyphicon-remove.rowAction'
    };

    this.setColumnsMetaInfo = function(columnsInfo) {
        this.columnsMeta = columnsInfo;
    };

    ///COLUMNS///
    this.countColumns = function(){
        return this._gridColumnHeaders.count();
    };
    this.getColumnHeader = function(columnName){
        var deferred = protractor.promise.defer();
        var pendingPromisesSize = 0;
        var columnMatch;
        var _this = this;

        this.countColumns().then(function(columnsNum){

            _this._gridColumnHeaders.each(function (columnHeader, idx) {
                columnHeader.getText().then(function (headerText) {
                    if (headerText === columnName) {
                        columnMatch = {header: columnHeader, index: idx};
                    }

                    pendingPromisesSize++;

                    if (columnsNum === pendingPromisesSize) {
                        deferred.fulfill(columnMatch);
                    }
                });
            });
        });

        return deferred.promise;
    };
    this.getColumnName = function(columnNum){
        return this._gridColumnHeaders.get(columnNum).getText();
    };
    this.clickColumn= function(columnNum){
        return this._gridColumnHeaders.get(columnNum).click();
    };
    this.isColumnSortable = function(columnNum){
        return utils.hasClass(this._gridColumnHeaders.get(columnNum), 'sortable');
    };
    this.isColumnSortedAsc = function(columnNum){
        return utils.hasClass(this._gridColumnHeaders.get(columnNum), 'sort-asc');
    };
    this.isColumnSortedDesc = function(columnNum){
        return utils.hasClass(this._gridColumnHeaders.get(columnNum), 'sort-desc');
    };
    this.isCheckColumn = function(columnNum){
        return utils.hasClass(this._gridColumnHeaders.get(columnNum), 'checkColumn');
    };

    ///ROWS///
    this.countRows = function(){
        return this._gridRows.count();
    };
    this.isRowActive = function(rowNum){
        return utils.hasClass(this._gridRows.get(rowNum), 'active');
    };
    this.clickRowCheckBox = function(rowNum){
        var deferred = protractor.promise.defer();
        var _this = this;
        this.getColumnHeader('').then(function (header) {
            _this._gridRows.get(rowNum).$$('td').get(header.index).$$('input').get(0).click().then(function(){
                deferred.fulfill();
            });
        });
        return deferred.promise;
    };
    this.invokeAction = function(rowNum, action){
        var deferred = protractor.promise.defer();
        var _this = this;
        this.getColumnHeader('Actions').then(function (header) {
            _this._gridRows.get(rowNum).$$('td').get(header.index).$$(action).click().then(function(){
                deferred.fulfill();
            });
        });
        return deferred.promise;
    };
    this.readCellValue = function(rowNum, columnName){
        var deferred = protractor.promise.defer();
        var _this = this;
        this.getColumnHeader(columnName).then(function (header) {
            _this._gridRows.get(rowNum).$$('td').get(header.index).$$('span').get(0).getText().then(function(cellValue){
                deferred.fulfill(cellValue);
            });
        });
        return deferred.promise;
    };
    this.findRowWithAction = function(action){
        var deferred = protractor.promise.defer();
        var foundRowNumber = -1;
        var _this = this;
        var pendingPromisesSize = 0;
        this.countRows().then(function(rowsNumber){
            _this.getColumnHeader('Actions').then(function (header) {
                _this._gridRows.each(function (row, idx) {
                    row.$$('td').get(header.index).$$(action).count().then(function(removeIconCount){
                        if (removeIconCount > 0 && foundRowNumber === -1) {
                            foundRowNumber = idx;

                        }

                        pendingPromisesSize++;

                        if (rowsNumber === pendingPromisesSize) {
                            deferred.fulfill(foundRowNumber);
                        }
                    });
                });
            });
        });
        return deferred.promise;
    };

    ///ROW DETAIL///
    this.isRowDetailsDisplayed = function(){
        var deferred = protractor.promise.defer();
        this._rowDetail.count().then(function (countValue) {
            deferred.fulfill(countValue === 1);
        });
        return deferred.promise;
    };
    this.collapseRowDetail = function(){
        return element(by.css('.hideDetails')).click();
    };
    this.openDetailsForRow = function(rowNum){
        return this._gridRows.get(rowNum).click();
    };

    ///BULK DELETE///
    this.isBulkDeleteEnabled = function(){
        return this._bulkDeleteBtn.isEnabled();
    };
    this.clickBulkDelete = function(){
        return this._bulkDeleteBtn.click();
    };
};

GridPage.prototype = Object.create({}, {
    _gridColumnHeaders: { get: function () {
        return element.all(by.repeater('columnHead in ::columnDefinitions'));
    }},
    _gridRows: { get: function () {
        return element.all(by.css('.grid-data-row'));
    }},
    _rowDetail: { get: function () {
        return element.all(by.css('.rowDetailContent'));
    }},
    _bulkDeleteBtn: { get: function () {
        return element(by.css('.gridBulkDeleteBtn'));
    }}
});

module.exports = GridPage;