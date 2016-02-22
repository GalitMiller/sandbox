Package with scripts to setup Bricata sensor.
=============================================

To review script, which will be executed on sensor:

    sensor-provisioning-init_sensor.sh generate -

To add additional options:

    sensor-provisioning-init_sensor.sh generate - GIT_SENSOR_BRANCH=sensor1

To store that script to a location:

    sensor-provisioning-init_sensor.sh generate /var/www/sensor-provisioning/init.sh GIT_SENSOR_BRANCH=sensor1

To execute scrip on sensor:

    sensor-provisioning-init_sensor.sh init root 10.130.206.2 22 GIT_SENSOR_BRANCH=sensor1
