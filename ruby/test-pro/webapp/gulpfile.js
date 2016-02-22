var gulp = require("gulp");
var clean = require("gulp-clean");
var uglify = require("gulp-uglify");
var minifyCSS = require("gulp-minify-css");
var minifyHTML = require("gulp-minify-html");
var jsonminify = require("gulp-jsonminify");
var sass = require("gulp-sass");
var concat = require("gulp-concat");
var flatten = require("gulp-flatten");
var jshint = require("gulp-jshint");
var csslint = require("gulp-csslint");
var newer = require("gulp-newer");
var gulpif = require("gulp-if");
var rename = require("gulp-rename");
var eventStream = require("event-stream");
var runSequence = require("run-sequence");
var html2js = require("gulp-ng-html2js");
var expect = require('gulp-expect-file');
var karma = require("gulp-karma");
var protractor = require("gulp-protractor").protractor;

var isProductionVersion = false;

var pagesHtml = ["src/application/*.html"];

var pagesJs = ["src/application/*.js"];

var pagesSass = ["src/scss/*.scss"];

var bootstrapSass = [
    "src/vendor/bootstrap-sass/bootstrap/*.scss",
    "src/vendor/bootstrap-sass/*.scss"
];

var modulesJs = [
    "src/modules/**/*module.js",
    "src/modules/**/*.js",
    "!src/modules/**/*_test.js"
];

var modulesTemplates = ["src/modules/**/*.html"];
var modulesStyles = "src/modules/**/*.scss";

var coreJs = [
    "src/uicore/**/*module.js",
    "src/uicore/**/*.js",
    "!src/uicore/**/*_test.js"
];

var coreTemplates = ["src/uicore/**/*.html"];
var coreStyles = "src/uicore/**/*.scss";

var srcSassVendor = "src/vendor";

var targetDirectory = "target";
var vendorTargetDirectory = targetDirectory + "/vendor";

var vendorJs = [
    "bower_components/angular/angular.min.js",
    "bower_components/angular-resource/angular-resource.min.js",
    "bower_components/angular-route/angular-route.min.js",
    "bower_components/angular-cookies/angular-cookies.min.js",
    "bower_components/angular-ui-bootstrap-bower/ui-bootstrap-tpls.min.js",
    "bower_components/ng-table/dist/ng-table.min.js",
    "bower_components/i18next/i18next.min.js",
    "bower_components/ng-i18next/dist/ng-i18next.min.js",
    "bower_components/angular-moment/angular-moment.min.js",
    "bower_components/moment/min/moment.min.js",
    "bower_components/ng-scrollable/min/ng-scrollable.min.js",
    "bower_components/angular-bootstrap-colorpicker/js/bootstrap-colorpicker-module.min.js"
];
var vendorCss = [
    "bower_components/ng-table/dist/ng-table.min.css",
    "bower_components/ng-scrollable/min/ng-scrollable.min.css",
    "bower_components/angular-bootstrap-colorpicker/css/colorpicker.min.css"
];

var imagesSrc = "src/media/images/**/*.{png,jpg,jpeg,gif,svg,ico}";
var bootstrapFontsSrc = "bower_components/bootstrap-sass/assets/fonts/**/*.{eot,svg,ttf,woff,woff2}";
var embededFonts = "src/media/fonts/**/*.{eot,svg,ttf,woff,woff2}";

var jsonMocks = "src/json-mocks/*.json";
var bundlesLocation = "src/i18n/*.json";
var configLocation = "src/config/*.json";

// Tasks
gulp.task("default", function(callback) {
    runSequence("build-dev", "watch", callback);
});

gulp.task("prod", function(callback) {
    isProductionVersion = true;
    modulesJs.push("!src/modules/api/services/api.module.dev.js");
    runSequence("clean",
        ["html", "templates", "coreTemplates", "sass", "vendor-source", "js", "media", "l10n", "config"],
        callback);
});

gulp.task("build-dev", function(callback) {
    modulesJs.push("!src/modules/api/services/api.module.prod.js");
    runSequence("clean",
        ["html", "templates", "coreTemplates", "sass", "vendor-source", "js", "media", "l10n", "config", "mocks"],
        callback);
});

gulp.task("test", function() {
    // to get files in karma.conf.js recognized, passing in
    // non-existent dir (from https://github.com/lazd/gulp-karma/issues/9)
    return gulp.src("./badpath")
        .pipe(karma({
            configFile: "karma.conf.js",
            action: "run"
        }));
});

gulp.task("e2e-local", function(done) {
    gulp.src("./src/e2e-tests/common/config.local.js")
        .pipe(rename("config.js"))
        .pipe(gulp.dest("./src/e2e-tests/common"));

    gulp.src(["./src/e2e-tests/**/*.js/"])
        .pipe(protractor({
            configFile: "protractor.conf.js"
        }));
});

gulp.task("e2e-server", function(done) {
    gulp.src("./src/e2e-tests/common/config.server.js")
        .pipe(rename("config.js"))
        .pipe(gulp.dest("./src/e2e-tests/common"));

    gulp.src(["./src/e2e-tests/**/*.js/"])
        .pipe(protractor({
            configFile: "protractor.conf.js"
        }));
});

gulp.task("clean", function() {
    // clean dist directory
    return gulp.src([targetDirectory], { read: false })
        .pipe(clean());
});

gulp.task("watch", function() {
    gulp.watch([pagesHtml], ["html"]);
    gulp.watch([modulesTemplates], ["templates"]);
    gulp.watch([coreTemplates], ["coreTemplates"]);
    gulp.watch([
        pagesSass,
        modulesStyles,
        coreStyles,
        bootstrapSass
    ], ["sass"]);
    gulp.watch([
        pagesJs,
        modulesJs,
        coreJs
    ], ["js"]);
    gulp.watch([
        imagesSrc,
        bootstrapFontsSrc,
        embededFonts
    ], ["media"]);
    gulp.watch([jsonMocks], ["mocks"]);
    gulp.watch([bundlesLocation], ["l10n"]);
    gulp.watch([configLocation], ["config"]);
});

gulp.task("html", function() {
    return eventStream.merge(
        compileHtml(pagesHtml, targetDirectory)
    );
});

gulp.task("templates", function() {
    return gulp.src(modulesTemplates)
        .pipe(minifyHTML({
            empty: true,
            quotes: true,
            spare: true
        }))
        .pipe(html2js({
            moduleName: 'bricata.ui.templates',
            prefix: 'modules/'
        }))
        .pipe(concat('templates.js'))
        .pipe(uglify())
        .pipe(gulp.dest(targetDirectory + '/modules/')); //Output folder
});

gulp.task("coreTemplates", function() {
    return gulp.src(coreTemplates)
        .pipe(minifyHTML({
            empty: true,
            quotes: true,
            spare: true
        }))
        .pipe(html2js({
            moduleName: 'bricata.uicore.templates',
            prefix: 'uicore/'
        }))
        .pipe(concat('coretemplates.js'))
        .pipe(uglify())
        .pipe(gulp.dest(targetDirectory + '/modules/')); //Output folder
});

gulp.task("sass", function() {
    return eventStream.merge(
        compileSass(pagesSass, targetDirectory + '/css'),
        compileSass(modulesStyles, targetDirectory + "/modules", "modules.css"),
        compileSass(coreStyles, targetDirectory + "/modules", "core.css"),
        compileVendorSass(bootstrapSass, vendorTargetDirectory + '/css')
    );
});

gulp.task("vendor-source", function() {
    return eventStream.merge(
        gulp.src(vendorJs)
            .pipe(expect({ errorOnFailure: true }, vendorJs))
            .pipe(newer(vendorTargetDirectory))
            .pipe(gulp.dest(vendorTargetDirectory + '/js')),
        gulp.src(vendorCss)
            .pipe(expect({ errorOnFailure: true }, vendorCss))
            .pipe(newer(vendorTargetDirectory))
            .pipe(gulp.dest(vendorTargetDirectory + '/css'))
    );
});

gulp.task("js", function() {
    return eventStream.merge(
        compileJs(pagesJs, targetDirectory + '/js'),
        compileJs(modulesJs,
                targetDirectory + "/modules", "modules.js"),
        compileJs(coreJs,
                targetDirectory + "/modules", "core.js")
    );
});

gulp.task("media", function() {
    return eventStream.merge(
        gulp.src(imagesSrc)
            .pipe(gulp.dest(targetDirectory + '/assets/images')),
        gulp.src(bootstrapFontsSrc)
            .pipe(gulp.dest(targetDirectory + '/vendor/fonts')),
        gulp.src(embededFonts)
            .pipe(gulp.dest(targetDirectory + '/vendor/fonts'))
    );
});

gulp.task("mocks", function() {
    return gulp.src(jsonMocks)
        .pipe(flatten())
        .pipe(gulp.dest(targetDirectory + "/json-mocks"));
});

gulp.task("l10n", function() {
    return gulp.src(bundlesLocation)
        .pipe(flatten())
        .pipe(gulpif(isProductionVersion, jsonminify()))
        .pipe(gulp.dest(targetDirectory + "/i18n"));
});

gulp.task("config", function() {
    return gulp.src(configLocation)
        .pipe(flatten())
        .pipe(gulpif(isProductionVersion, jsonminify()))
        .pipe(gulp.dest(targetDirectory + "/config"));
});

function compileHtml(source, destination) {

    return gulp.src(source)
        .pipe(newer(targetDirectory))
        .pipe(gulpif(isProductionVersion, minifyHTML({empty:true,spare:true})))
        .pipe(gulp.dest(destination));
}

function compileSass(source, destination, concatName) {

    var doConcat = (concatName) ? true : false;
    concatName = (!concatName) ? "fakename" : concatName;

    return gulp.src(source)
        .pipe(sass())
        .pipe(csslint("csslintrc.json"))
        .pipe(csslint.reporter())
        .pipe(gulpif(isProductionVersion, minifyCSS()))
        .pipe(gulpif(doConcat, concat(concatName)))

        .pipe(gulp.dest(destination));
}

function compileVendorSass(source, destination) {
    return gulp.src(source)
        .pipe(sass())
        .pipe(gulpif(isProductionVersion, minifyCSS()))
        .pipe(gulp.dest(destination));
}

function compileJs(source, destination, concatName) {

    if (concatName) {
        return gulp.src(source)
            .pipe(jshint())
            .pipe(jshint.reporter("default"))
            .pipe(gulpif(isProductionVersion, uglify({mangle:false})))
            .pipe(concat(concatName))
            .pipe(gulp.dest(destination));
    } else {
        return gulp.src(source)
            .pipe(newer(targetDirectory))
            .pipe(jshint())
            .pipe(jshint.reporter("default"))
            .pipe(gulpif(isProductionVersion, uglify({mangle:false})))
            .pipe(gulp.dest(destination));
    }
}
