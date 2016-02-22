var Configuration = function() {

    this.baseUrl = 'https://192.168.240.83/static/';
    this.login = {
        pageUrl: 'https://192.168.240.83/users/login',
        user: 'bricata@bricata.com',
        password: 'Administrator'
    };
    this.policyUrls = {
        grid: '#/policies',
        wizard: '#/policies/wizard'
    };
    this.categoryUrls = {
        grid: '#/signatures/categories',
        wizard: '#/signatures/categories/wizard'
    };
};

module.exports = new Configuration();