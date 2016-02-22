#!/bin/bash
set -ue

BIN_DIR="$(dirname "$(readlink -f "$0")")"  # Full path to directory, where this script is located"
. "$BIN_DIR"/../settings.sh

TARGET_OS="ubuntu"
TARGET_DIST="trusty"
TARGET_COMPONENT="bpac"

# Clean before kicking the build
DO_CLEANUP="${DO_CLEANUP:-yes}"
DO_INSTALL_BUILD_DEPS="${DO_INSTALL_BUILD_DEPS:-no}"

# FIXME: Change to option and use local directory only if option is undefined
SOURCE_DIR="$BIN_DIR"

# let's prepare the folder where we will store all *.deb
PACKAGE_BIN_DIR=$SOURCE_DIR/deb-bin
PACKAGE_REPO_DIR=$SOURCE_DIR/deb-repo

# Install build dependencies
if [ "$DO_INSTALL_BUILD_DEPS" == "yes" ];
then
  sudo yum -y install fakeroot dh-make dpkg
fi

[ -x /usr/bin/dh_make -a -x /usr/bin/dpkg -a -x /usr/bin/fakeroot -a -x /usr/bin/reprepro ] || {
  echo "ERROR: This script requires fakeroot, dh-make, dpkg, and reprepro. Please, install them using command \"sudo yum -y install fakeroot dh-make dpkg reprepro\"." >&2
  exit 1
}

# Cleanup (in case we already have those dirs created by previous run)
if [ "$DO_CLEANUP" == "yes" ];
then
  rm -rf "$PACKAGE_BIN_DIR" "$PACKAGE_REPO_DIR/$TARGET_OS" || {
    echo "ERROR: Cannot remove directories \"$PACKAGE_BIN_DIR\" and/or \"$PACKAGE_REPO_DIR/$TARGET_OS\"." >&2
    exit 1
  }
fi

mkdir -p "$PACKAGE_BIN_DIR/$TARGET_OS" "$PACKAGE_REPO_DIR" || {
  echo "ERROR: Cannot create directories \"$PACKAGE_BIN_DIR\" and/or \"$PACKAGE_REPO_DIR/$TARGET_OS\"." >&2
  exit 1
}


# Cycle through the folders and build DEBs
for PKG_DIR in "$SOURCE_DIR"/*/src/debian
do
  PKG_DIR="${PKG_DIR%/src/debian}"  # Strip "/src/debian" suffix

  # Ignore non directories
  if [ ! -d "$PKG_DIR" ]
  then
    continue
  fi

  # Init in-loop variables
  _PKG="${PKG_DIR##*/}" # Strip path to last slash
  _PKG_DIR="$PKG_DIR"
  _PKG_SRC_DIR="$_PKG_DIR/src"
  _PKG_BUILD_DIR="$_PKG_DIR/build"
  _PKG_BUILDROOT_DIR="$_PKG_DIR/buildroot" # not in use for now

  # Calculate package revision using length of changelog in git
  _PKG_GITREV=$(git log --oneline -- "$_PKG_DIR" 2>/dev/null | wc -l)

  # Set package version using BPAC_VERSION variable and length of git changelog
  VERSION="${BPAC_VERSION}.$_PKG_GITREV"

  echo ""
  echo "Building Debian (*.deb) package \"$_PKG\" in \"$PKG_DIR\" directory."

  # Cleanup (in case we already have those dirs created by previous run)
  if [ "$DO_CLEANUP" == "yes" ]
  then
    rm -rf "$_PKG_BUILD_DIR" "$_PKG_BUILDROOT_DIR"
  fi

  # Create build dir
  mkdir -p "$_PKG_BUILD_DIR" "$_PKG_BUILDROOT_DIR"


  # Copy files to buildroot directory. We can do this just with
  # copy because we are not doing any compilation.
  # That's an analog of %install section in rpm-build.
  mkdir -p "$_PKG_BUILD_DIR/$_PKG-$VERSION"
  cp -a "$_PKG_SRC_DIR/"* "$_PKG_BUILD_DIR/$_PKG-$VERSION/"

  # Update package version in debian/changelog
  sed -i "s/@VERSION@/$VERSION/g" "$_PKG_BUILD_DIR/$_PKG-$VERSION/debian/changelog"

  pushd "$_PKG_BUILD_DIR/$_PKG-$VERSION"

  # Run dh-make
  dh_make --single --createorig --yes || {
    echo "WARNING: dh_make command issued an error. You may ignore it if it is relatated to existing \"debian\" folder." >&2
  }

  # Build the package
  dpkg-buildpackage -b -d || {
    echo "WARNING: There were errors and/or warnings detected when building package $_PKG. Check the log file above and make corresponding corrections." >&2
  }

  popd

  # Copy freshly built packages to PACKAGE_BIN_DIR
  echo "Copying freshly built *.deb files to $PACKAGE_BIN_DIR"
  cp -v -a "$_PKG_BUILD_DIR"/*.deb "$PACKAGE_BIN_DIR/" || {
    echo "Cannot copy *.deb files from \"$_PKG_BUILD_DIR\" directory to \"$PACKAGE_BIN_DIR/\" directory." >&2
    exit 1
  }

done

echo ""
echo "Package build completed"
echo ""
echo "[ Packages built: ]"
ls -1 "$PACKAGE_BIN_DIR"

###
#  Generate repository metadata
###

# Import GPG keys
gpg --import "$SOURCE_DIR/etc/bpac.gpg.key" || :
gpg --allow-secret-key-import --import "$SOURCE_DIR/etc/bpac_secret.gpg.key" || :

# Create a reprepro configuration directory
mkdir -p "$PACKAGE_REPO_DIR/$TARGET_OS/conf"
cp -av "$SOURCE_DIR/etc/options" "$PACKAGE_REPO_DIR/$TARGET_OS/conf"
cp -av "$SOURCE_DIR/etc/distributions" "$PACKAGE_REPO_DIR/$TARGET_OS/conf"
echo "verbose" >> "$PACKAGE_REPO_DIR/$TARGET_OS/conf/options"
echo "basedir $PACKAGE_REPO_DIR/$TARGET_OS" >> "$PACKAGE_REPO_DIR/$TARGET_OS/conf/options"

# Adding packages to the repository
pushd "$PACKAGE_REPO_DIR/$TARGET_OS"
reprepro -Vb . export || {
  echo "ERROR: Cannot generate all index files for the specified distributions using command \"reprepo -Vb . export\" in \"$PACKAGE_REPO_DIR/$TARGET_OS\" directory." >&2
  exit 1
}
reprepro -V includedeb "$TARGET_DIST" "$PACKAGE_BIN_DIR"/*.deb || {
  echo "ERROR: Cannot include given binary Debian packages (.deb) in the specified distribution using command \"reprepro -V includedeb $TARGET_DIST" "$PACKAGE_BIN_DIR"/*.deb "\" in \"$PACKAGE_REPO_DIR/$TARGET_OS\" directory." >&2
  exit 1
}
popd

# Copy public GPG key so it can be imported by users
cp -av "$SOURCE_DIR/etc/bpac.gpg.key" "$PACKAGE_REPO_DIR/$TARGET_OS/"

echo "Repository build completed!"

### DEBUG: Copy repo to local machine's web folder
# pushd $PACKAGE_REPO_DIR
# sudo rm -rf /var/www/repo/ubuntu
# sudo cp -a ./ /var/www/repo/
# popd

