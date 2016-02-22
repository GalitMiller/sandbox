This is directory for various RPM packages. Some packages can be also
located of this directory, but they need to be explicitly archived in
build.sh.

Packages can be built in two modes: "mock" mode, when each package is
built in isolation in it own chroot directory using mock, or fast mode,
when each package is built using host packages and libraries.

"Mock" mode is good because it allows to test packages better in
isolation and because package dependencies are installed automatically.

Fast mode is good because it is fast: dependencies are installed once,
manually, and then time is spent on actual building of packages only.

Directory build-scripts contains modules for build.sh. Directory
mock-config contains configuration for mock (with "bpac-ext" yum
repository with third party packages which are essential for building og
packages in clean environment).

Subdirectory "spec" in each directory contains .spec-file, which has
complete description of package, it dependencies, files and building
procedure.
