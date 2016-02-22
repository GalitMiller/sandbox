exports.config = {
    seleniumServerJar: './node_modules/protractor/selenium/selenium-server-standalone-2.45.0.jar',
    specs: ['./src/e2e-tests/tests/**/*.js'],
    baseUrl: '',
    capabilities: {
        'browserName': 'chrome'
    },

    // Options to be passed to Jasmine-node.
    jasmineNodeOpts: {
        showColors: true,
        defaultTimeoutInterval: 30000
    }
};