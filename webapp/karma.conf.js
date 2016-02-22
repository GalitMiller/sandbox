module.exports = function(config) {
	config.set({
		files: [
			"target/vendor/css/*.css",
			"target/css/main.css",

            "bower_components/jquery/dist/jquery.js",
            "target/vendor/js/angular.min.js",
            "target/vendor/js/ui-bootstrap-tpls.min.js",
            "target/vendor/js/angular-resource.min.js",
            "target/vendor/js/angular-route.min.js",
            "target/vendor/js/angular-cookies.min.js",
            "target/vendor/js/ng-table.min.js",
            "target/vendor/js/i18next.min.js",
            "target/vendor/js/ng-i18next.min.js",
            "target/vendor/js/moment.min.js",
            "target/vendor/js/angular-moment.min.js",
            "target/vendor/js/ng-scrollable.min.js",
            "target/vendor/js/bootstrap-colorpicker-module.min.js",
            "bower_components/angular-mocks/angular-mocks.js",
            "bower_components/jasmine-jquery/lib/jasmine-jquery.js",

            "target/modules/core.js",
            "target/modules/core.css",
            "target/modules/coretemplates.js",
			"target/modules/modules.js",
            "target/modules/modules.css",
            "target/modules/templates.js",
            {pattern: "src/json-mocks/*.json", watched: false, included: false, served: true},
            {pattern: "src/media/**/*.*", watched: false, included: false, served: true},
            {pattern: "src/config/app_conf.json", watched: true, served: true, included: false},
            {pattern: "src/i18n/bundle_en.json", watched: true, served: true, included: false},
			"src/application/main.js",
			"src/uicore/**/*_test.js",
            "src/modules/**/*_test.js"
		],
        proxies:  {
            '/i18n/': '/base/src/i18n/'
        },
		frameworks: ["phantomjs-shim", "jasmine"],
		plugins: ["karma-jasmine", "karma-phantomjs-launcher", "karma-phantomjs-shim",
            "karma-junit-reporter", "karma-coverage", "karma-ng-html2js-preprocessor"],
		browsers: ["PhantomJS"],
        phantomjsLauncher: {
            exitOnResourceError: true
        },
		logLevel: config.LOG_DEBUG,
		singleRun: true,
		reporters: ["progress", "junit", "coverage"],
		junitReporter: {
			outputFile: "test/test-results.xml"
		},
		preprocessors: {
			"target/modules/*.js": "coverage",
			"src/modules/*/**/*.html": ["ng-html2js"]
		},
		coverageReporter: {
			type: "lcov",
			dir: "coverage/"
		},
		ngHtml2JsPreprocessor: {
			stripPrefix: "src/"
		}
	});
};