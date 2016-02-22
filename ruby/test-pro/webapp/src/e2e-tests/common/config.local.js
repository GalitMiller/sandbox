var Configuration = function() {

    this.baseUrl = 'http://localhost:63342/webapp/target/';
    this.policyUrls = {
        grid: 'index.html#/policies',
        wizard: 'index.html#/policies/wizard'
    };
    this.categoryUrls = {
        grid: 'index.html#/signatures/categories',
        wizard: 'index.html#/signatures/categories/wizard'
    };
};

module.exports = new Configuration();