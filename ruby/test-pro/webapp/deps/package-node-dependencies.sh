#!/bin/bash

fpm -s npm -t rpm bower
fpm -s npm -t rpm gulp
fpm -s npm -t rpm gulp-sass
fpm -s npm -t rpm gulp-clean
fpm -s npm -t rpm gulp-uglify
fpm -s npm -t rpm gulp-concat
fpm -s npm -t rpm gulp-jshint
fpm -s npm -t rpm gulp-minify-css
fpm -s npm -t rpm gulp-minify-html
fpm -s npm -t rpm gulp-csslint
fpm -s npm -t rpm gulp-if
fpm -s npm -t rpm gulp-newer
fpm -s npm -t rpm gulp-connect
fpm -s npm -t rpm gulp-flatten
fpm -s npm -t rpm gulp-jsonminify
fpm -s npm -t rpm gulp-ng-html2js
fpm -s npm -t rpm gulp-jasmine
fpm -s npm -t rpm gulp-expect-file
fpm -s npm -t rpm gulp-rename

fpm -s npm -t rpm run-sequence
fpm -s npm -t rpm event-stream

fpm -s npm -t rpm gulp-protractor
fpm -s npm -t rpm protractor
fpm -s npm -t rpm jshint-stylish
fpm -s npm -t rpm jasmine-core
fpm -s npm -t rpm phantomjs

fpm -s npm -t rpm karma
fpm -s npm -t rpm karma-chrome-launcher
fpm -s npm -t rpm karma-firefox-launcher

# Delete /usr/bin entry manually when editor starts
fpm -s npm -t rpm -x '**/karma' -x '**/phantomjs' --depends node-karma --depends node-phantomjs --name node-karma-phantomjs-launcher -e karma-phantomjs-launcher
fpm -s npm -t rpm -x '**/karma' --depends node-karma --name node-karma-junit-reporter -e karma-junit-reporter
fpm -s npm -t rpm -x '**/karma' --depends node-karma --name node-karma-coverage -e karma-coverage
fpm -s npm -t rpm -x '**/karma' --depends node-karma --name node-karma-ng-html2js-preprocessor -e karma-ng-html2js-preprocessor
fpm -s npm -t rpm -x '**/karma' -x '**/jasmine-core' --depends node-karma --depends node-jasmine-core --name node-karma-jasmine -e karma-jasmine
fpm -s npm -t rpm -x '**/karma' --depends node-karma --name node-gulp-karma -e gulp-karma
fpm -s npm -t rpm -x '**/karma' --depends node-karma --depends node-phantomjs --name node-karma-phantomjs-shim karma-phantomjs-shim
