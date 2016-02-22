#!/bin/bash

# Version to use for RPM packages.
BPAC_VERSION="1.5.3"

# Set to yes to build packages without using "mock", using rpmbuild, so
# build will not be "clean", but it will be faster a bit.
RPMS_FAST_BUILD="yes"

[ ! -s local_settings.sh ] || source local_settings.sh
