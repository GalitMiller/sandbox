#!/bin/bash
set -ue

# Convert bower package into RPM package.
# Author: Volodymyr M. Lisivka <vlisivka@gmail.com>
# Bower components are installed to /usr/lib/bower_components, then they
# can be linked from this directory to project working directory.
bower2srpm() {
  local PACKAGE_NAME="${1:?Argument required: Name of bower package.}"
  local PACKAGE_VERSION="${2:?Argument required: Version of bower package.}"

  # Create temporary directory for bower package, archive, and .spec file
  local BUILD_TMP_DIR="$(mktemp -d)"

  # Install bower package
  ( cd "$BUILD_TMP_DIR" && bower install "$PACKAGE_NAME#$PACKAGE_VERSION" ) || {
    echo "ERROR: Cannot install bower package \"$PACKAGE_NAME $PACKAGE_VERSION\"." >&2
    return 1
  }

  # Create .spec file
  local SPEC_FILE="bower-$PACKAGE_NAME.spec"
  cat <<SPEC_FILE >"$BUILD_TMP_DIR/bower_components/$SPEC_FILE"

Name:           bower-$PACKAGE_NAME
Version:        $PACKAGE_VERSION
Release:        1%{?dist}
Summary:        Bower package of $PACKAGE_NAME
Group:          Bower
License:        Unknown
URL:            $(bower lookup "$PACKAGE_NAME" | cut -d' ' -f 2)
Source:         %{name}-%{version}.tar.gz
BuildArch:      noarch

%description

$(bower info "$PACKAGE_NAME#$PACKAGE_VERSION")


%prep
%setup -n $PACKAGE_NAME

%install
rm -rf "\$RPM_BUILD_ROOT"
mkdir -p "\$RPM_BUILD_ROOT/usr/lib/bower_components/$PACKAGE_NAME/"

cp -a * "\$RPM_BUILD_ROOT/usr/lib/bower_components/$PACKAGE_NAME/"

%clean
rm -rf "\$RPM_BUILD_ROOT"


%files
%defattr(0644,root,root,755)

/usr/lib/bower_components/$PACKAGE_NAME

%changelog
* $(LANG=C date '+%a %b %d %Y') $(getent passwd "$USER" | cut -d ':' -f 5 | cut -d ',' -f 1) - $PACKAGE_VERSION-1
- Initial version.
SPEC_FILE

  # Create .tar.gz archive of directory and .spec file
  local TAR_FILE="$BUILD_TMP_DIR/bower-$PACKAGE_NAME-$PACKAGE_VERSION.tar.gz"
  tar -czf "$TAR_FILE" -C "$BUILD_TMP_DIR/bower_components" "$SPEC_FILE" "$PACKAGE_NAME"  || {
    echo "ERROR: Cannot create archive of \"$BUILD_TMP_DIR/bower_components/$PACKAGE_NAME\" directory." >&2
    return 1
  }

  rpmbuild -ta "$TAR_FILE" || {
    echo "ERROR: Cannot build RPM package from \"$BUILD_TMP_DIR/$TAR_FILE\"." >&2
    return 1
  }

  # Cleanup
  rm -rf "$BUILD_TMP_DIR"
}

[ "${DEFINE_ONLY:-no}" == "yes" ] || {
  bower2srpm "$@"
}
