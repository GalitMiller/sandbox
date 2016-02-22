var GridSpecification = function (grid, gridFilter) {
    this._grid = grid;
    this._gridFilter = gridFilter;

    this.checkAllColumns = function(){
        expect(this._grid.countColumns()).toEqual(this._grid.columnsMeta.length);

        for (var i = 0; i < this._grid.columnsMeta.length; i++){
            expect(this._grid.getColumnName(i)).toEqual(this._grid.columnsMeta[i].label);

            if (this._grid.columnsMeta[i].isCheck) {

                expect(this._grid.isColumnSortable(i)).toBeFalsy();
                expect(this._grid.isCheckColumn(i)).toBeTruthy();

            } else if (this._grid.columnsMeta[i].isActionCol) {

                expect(this._grid.isCheckColumn(i)).toBeFalsy();
                expect(this._grid.isColumnSortable(i)).toBeFalsy();

            } else if (this._grid.columnsMeta[i].isDefaultSort) {

                expect(this._grid.isCheckColumn(i)).toBeFalsy();
                expect(this._grid.isColumnSortable(i)).toBeTruthy();
                this.checkColumnSorted(i);

            } else {

                expect(this._grid.isCheckColumn(i)).toBeFalsy();
                expect(this._grid.isColumnSortable(i)).toBeTruthy();

            }
        }
    };

    this.checkColumnIsNotSorted = function(columnNum){
        expect(this._grid.isColumnSortedAsc(columnNum)).toBeFalsy();
        expect(this._grid.isColumnSortedDesc(columnNum)).toBeFalsy();
    };

    this.checkColumnSorted = function(columnNum, isDesc){
        if (isDesc) {
            expect(this._grid.isColumnSortedDesc(columnNum)).toBeTruthy();
        } else {
            expect(this._grid.isColumnSortedAsc(columnNum)).toBeTruthy();
        }
    };

    this.checkRowsPresent = function(){
        expect(this._grid.countRows()).toBeGreaterThan(0);
    };

    this.checkIsBulkDeleteAllowed = function(isAllowed){
        if (isAllowed) {
            expect(this._grid.isBulkDeleteEnabled()).toBeTruthy();
        } else {
            expect(this._grid.isBulkDeleteEnabled()).toBeFalsy();
        }
    };

    this.checkDetailsDisplayedForRow = function(rowNum, isDisplayed) {
        if (isDisplayed) {
            expect(this._grid.isRowActive(rowNum)).toBeTruthy();
            expect(this._grid.isRowDetailsDisplayed()).toBeTruthy();
        } else {
            expect(this._grid.isRowActive(rowNum)).toBeFalsy();
            expect(this._grid.isRowDetailsDisplayed()).toBeFalsy();
        }
    };

    this.checkRowDetailsListsAreNotEmpty = function(listsCountsArr){
        for (var i = 0; i < listsCountsArr.length; i++){
            expect(listsCountsArr[i]).toBeGreaterThan(0);
        }
    };

    this.checkFilterValues = function(search, option, startDate, endDate){
        if (search !== null) {
            expect(this._gridFilter.getSearchFilter()).toBe(search);
        }
        if (option !== null) {
            expect(this._gridFilter.getCurrentFilterOption()).toBe(option);
        }
        if (startDate !== null) {
            expect(this._gridFilter.getStartDateValue()).toBe(startDate);
        }
        if (endDate !== null) {
            expect(this._gridFilter.getEndDateValue()).toBe(endDate);
        }
    };

    this.checkModalDisplayed = function(modal, isDisplayed){
        if (isDisplayed) {
            expect(modal.isModalDisplayed()).toBeTruthy();
        } else {
            expect(modal.isModalDisplayed()).toBeFalsy();
        }
    };
};

module.exports = GridSpecification;