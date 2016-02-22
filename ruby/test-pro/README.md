## Bricata ProAccel Configuration Management Console project


Docker
======

Build and run
-------------

To build docker container, use following command ./build.sh .

To run built container, use command ./run.sh .

Applying changes without rebuilds
---------------------------------

Sometimes, developers need to test their changes in container. They have following choices:

  * do their changes in container directly;
  * create full text-mode development environment in container;
  * connect to server remotelly from IDE and copy files into container;
  * transfer packages with changes from host into container and reinstall them;
  * map directory from host into container.

To do changes directly in container, just enter container using command
"docker exec -it bpac bash", then launch "mc" file manager and edit any
files you want using mcedit or vim. When changes are tested, just
copy-paste them back to project using clipboard or by copying whole files
using "docker exec cat /path/to/remote/file > ./path/to/local/file", or
by using mc "shell connection" feature to connect back to linux host.

To create full development environment in container, just install any
packages you need, then connect to git repository and download sources as
usual.

