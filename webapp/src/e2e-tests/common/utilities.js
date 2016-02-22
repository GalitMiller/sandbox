
exports.hasClass = function (element, cls) {
    return element.getAttribute('class').then(function (classes) {
        return classes.split(' ').indexOf(cls) !== -1;
    });
};

exports.checkHasError = function (element) {
    return element.getAttribute('tooltip').then(function (tooltip) {
        return tooltip && tooltip.length > 0;
    });
};

if (!String.prototype.endsWith) {
    Object.defineProperty(String.prototype, "endsWith", {
            value: function (searchString, position) {
                var subjectString = this.toString();
                if (position === undefined || position > subjectString.length) {
                    position = subjectString.length;
                }
                position -= searchString.length;
                var lastIndex = subjectString.indexOf(searchString, position);
                return lastIndex !== -1 && lastIndex === position;
            }
        }
    );
}