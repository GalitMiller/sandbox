FROM 192.168.240.82:5000/bricata

MAINTAINER Volodymyr M. Lisivka <vlisivka@softserveinc.com>

# Application server (httpd->flask->app) is listen on 5080,
# but snorby will redirect without port, so port 80 is necessary on host
# to work.
EXPOSE 5080

# mysql(mariadb) database can be used from host
EXPOSE 3306

# IP of CMC for sensor provisioning script
ENV CMC_IP 192.168.240.83

# TimeZone for CMC
ENV CMC_TZ UTC

# Copy configuration of SoftServe local repository with external dependencies for BPAC.
COPY dockerfiles/etc/yum.repos.d/bpac-ext.repo /etc/yum.repos.d/

# Install required packages for application.
RUN yum -y install epel-release \
 && yum -y install \
    createrepo_c \
    bash-completion \
    dos2unix \
    git \
    mod_ssl \
    sudo \
    make \
    mariadb-server \
    mc \
    mysql-connector-python \
    redis \
    jdk1.8.0_45 \
    # python-flask-restless-0.17.1dev is patched
    python-flask-restless-0.17.1dev \
    python-flask-0.10.1 \
    python-flask-cache-0.13.1 \
    python-flask-celery-helper-1.1.0 \
    python-flask-login-0.2.11 \
    python-flask-sqlalchemy-2.0 \
    MySQL-python-1.2.5 \
    python-sqlalchemy-0.9.9 \
    python-sqlalchemy-continuum-1.1.5 \
    python-sqlalchemy-utils-0.30.0 \
    python-sqlalchemy-migrate-0.9.6 \
    python-awesome-slugify-1.6.4 \
    python-celery-3.1.17 \
    python-colour-0.1.1 \
    GitPython-1.0.1 \
    python-inflection-0.3.1 \
    python-isotopic-logging-1.0.1 \
    python-logsna-1.2 \
    python-netifaces-0.10.4 \
    python-paramiko-1.15.2 \
    python-pyasn1-0.1.7 \
    python-redis-2.10.3 \
    python-schematics-1.0.4 \
    python-scp-0.10.0 \
    python-superdict-1.0.3 \
    python-twisted-15.1.0 \
    python-unipath-1.1 \
    bpython-0.13 \
    python-flask-script-2.0.5 \
    pylint-1.4.3 \
    python-dateutil \
    python-mimerender \
    python-tempita \
    python-decorator \
    python-sqlparse \
 && yum -y swap -- remove fakesystemd -- install systemd systemd-libs initscripts

# Copy APT repository for sensor packages
COPY debs/deb-repo /var/www/repo

# Copy yum configuration and locally built packages (to avoid need of temporary web-server to deploy packages).
COPY dockerfiles/etc/yum.repos.d/bpac-local.repo /etc/yum.repos.d/
COPY dockerfiles/var/lib/bpac-yum-repo/* /var/lib/bpac-yum-repo/
WORKDIR /var/lib/bpac-yum-repo/
RUN createrepo_c .

# Install built packages and enable services
RUN yum install -y \
  bpac-bricata-workers \
  bpac-celery \
  bpac-cmc-user \
  bpac-first-boot \
  bpac-httpd-conf \
  bpac-pki \
  bpac-rules-git \
  bpac-sensor-provisioning \
  bpac-oinkmaster-updater \
  bpac-backend \
  bpac-webapp \
  bpac-bricata \
  bpac-mysql \
  bpac-self-check \
  && \
systemctl enable \
  httpd \
  mariadb \
  redis \
  celery \
  celerybeat \
  bpac-first-boot \
  bpac-rules-git \
  bpac-bricata-workers \
# Check ISA tables before MySQL startup
  bpac-mysql-myisamcheck \
# Check all tables after MySQL startup
  bpac-mysql-mysqlcheck

# Copy container label to web /static/ directory, so it can be checked via web
COPY dockerfiles/var/www/webapp/target/VERSION.txt /var/www/webapp/target/

