#!/usr/bin/make -f

all: build

build: node_modules bower_components gulp_build_prod

node_modules:
	npm install

bower_components:
	bower --allow-root install

gulp_build_dev:
	gulp build-dev

gulp_build_prod:
	gulp prod

# Requires Karma and PhantomJS (headless browser)
test:
	karma start --browsers PhantomJS

clean:
	rm -rf target

dist-clean: clean
	rm -rf bower_components node_modules

.PHONY: all build node_modules bower_component gulp_build_dev clean dist-clean fix_newlines build_for_backend change_path_to_json test

