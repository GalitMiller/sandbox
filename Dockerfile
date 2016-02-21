FROM centos:centos7

MAINTAINER Volodymyr M. Lisivka <vlisivka@softserveinc.com>

# RoR will listen on port 3000
# EXPOSE 3000

# Systemd needs /sys/fs/cgroup directory to be mounted from host
VOLUME /sys/fs/cgroup

# Systemd needs /run directory to be fresh at every container startup
VOLUME /run

# Set English language and UTF-8 encoding as default for commands and
# applications
ENV LANG en_US.utf8

# Set term variable to avoid error about unknown terminal in interactive commands (e.g. mysql client)
ENV TERM xterm

# Set PATH variable
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin


RUN \
    yum update -y && \
    yum install -y epel-release && \
    yum install -y \
    createrepo_c \
    tar \
    wget \
    initscripts \
    dbus \
    mysql-server \
    mysql-connector-python \
    npm \
    redis \
    mod_ssl \
    policycoreutils \
    sendmail \
# For developers 
    bash-completion \
    htop \
    mc \
    vim-enhanced \
    initscripts \
    net-tools \
    # Cache these packages for faster building of BPAC container.
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
    python-isotopic-logging-1.0.0 \
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
    "python-gitdb >= 0.6.4" \
    python-dateutil \
    python-mimerender \
    python-tempita \
    python-decorator \
    python-sqlparse \
# Other dependencies (copied from yum report) for faster building of bpac container
    atk \
    avahi-libs \
    cairo \
    cups-libs \
    fipscheck \
    fipscheck-lib \
    gdk-pixbuf2 \
    graphite2 \
    gtk2 \
    harfbuzz \
    hicolor-icon-theme \
    hwdata \
    jasper-libs \
    jbigkit-libs \
    libXcomposite \
    libXcursor \
    libXdamage \
    libXfixes \
    libXi \
    libXinerama \
    libXrandr \
    libXxf86vm \
    libdrm \
    libedit \
    libgnome-keyring \
    libpciaccess \
    libthai \
    libtiff \
    libwebp \
    mesa-libEGL \
    mesa-libGL \
    mesa-libgbm \
    mesa-libglapi \
    openssh \
    openssh-clients \
    pango \
    perl-Error \
    perl-Git \
    perl-TermReadKey \
    pixman \
    pyOpenSSL \
    pycairo \
    pygobject2 \
    pygtk2 \
    pyparsing \
    pyserial \
    python-amqp \
    python-anyjson \
    python-astroid \
    python-async \
    python-backports \
    python-backports-ssl_match_hostname \
    python-billiard \
    python-characteristic \
    python-crypto \
    python-ecdsa \
    python-idna \
    python-kombu \
    python-logilab-common \
    python-mimeparse \
    python-mock \
    python-pillow \
    python-pyasn1-modules \
    python-pygments \
    python-regex \
    python-service-identity \
    python-setuptools \
    python-six \
    python-smmap \
    python-unidecode \
    python-urwid \
    python-zope-interface \
    pytz \
    rsync \
    tix \
    tkinter \
# End of copy-pasted dependencies
    && \
# Remove fake systemd, which is installed by default to centos7 container, at time of write,
# by real systemd.
    yum -y swap -- remove fakesystemd -- install systemd systemd-libs

# Change target init stage from from graphical mode to multiuser text-only mode
RUN systemctl disable graphical.target ; systemctl enable multi-user.target

# Copy configuration of SoftServe local repository with external dependencies for BPAC.
COPY dockerfiles/etc/yum.repos.d/bpac-ext.repo /etc/yum.repos.d/

# Install ruby gems earlier to cache them in docker file.
RUN yum install -y \
  wkhtmltox \
  passenger \
  mod_passenger \
  ruby193-ruby \
  ruby193-ruby-devel \
  ruby193-rubygem-actionmailer \
  ruby193-rubygem-actionpack \
  ruby193-rubygem-activemodel \
  ruby193-rubygem-activerecord \
  ruby193-rubygem-activeresource \
  ruby193-rubygem-activesupport \
  ruby193-rubygem-addressable \
  ruby193-rubygem-ansi \
  ruby193-rubygem-arel \
  ruby193-rubygem-bcrypt-ruby \
  ruby193-rubygem-bigdecimal \
  ruby193-rubygem-builder \
  ruby193-rubygem-bundler \
  ruby193-rubygem-bundler-unload \
  ruby193-rubygem-cancan \
  ruby193-rubygem-capistrano \
  ruby193-rubygem-capybara \
  ruby193-rubygem-childprocess \
  ruby193-rubygem-chronic \
  ruby193-rubygem-closure-compiler \
  ruby193-rubygem-daemons \
  ruby193-rubygem-data_objects \
  ruby193-rubygem-delayed_job \
  ruby193-rubygem-devise \
  ruby193-rubygem-devise_invitable \
  ruby193-rubygem-diff-lcs \
  ruby193-rubygem-dm-active_model \
  ruby193-rubygem-dm-aggregates \
  ruby193-rubygem-dm-ar-finders \
  ruby193-rubygem-dm-chunked_query \
  ruby193-rubygem-dm-constraints \
  ruby193-rubygem-dm-core \
  ruby193-rubygem-dm-devise \
  ruby193-rubygem-dm-do-adapter \
  ruby193-rubygem-dm-migrations \
  ruby193-rubygem-dm-mysql-adapter \
  ruby193-rubygem-dm-observer \
  ruby193-rubygem-dm-pager \
  ruby193-rubygem-dm-rails \
  ruby193-rubygem-dm-serializer \
  ruby193-rubygem-dm-timestamps \
  ruby193-rubygem-dm-transactions \
  ruby193-rubygem-dm-types \
  ruby193-rubygem-dm-validations \
  ruby193-rubygem-dm-visualizer \
  ruby193-rubygem-dm-zone-types \
  ruby193-rubygem-do_mysql \
  ruby193-rubygem-env \
  ruby193-rubygem-erubis \
  ruby193-rubygem-eventmachine \
  ruby193-rubygem-fastercsv \
  ruby193-rubygem-ffi \
  ruby193-rubygem-geoip \
  ruby193-rubygem-highline \
  ruby193-rubygem-hike \
  ruby193-rubygem-home_run \
  ruby193-rubygem-i18n \
  ruby193-rubygem-io-console \
  ruby193-rubygem-jammit \
  ruby193-rubygem-jquery-rails \
  ruby193-rubygem-json \
  ruby193-rubygem-json_pure \
  ruby193-rubygem-launchy \
  ruby193-rubygem-letter_opener \
  ruby193-rubygem-mail \
  ruby193-rubygem-mime-types \
  ruby193-rubygem-minitest \
  ruby193-rubygem-multi_json \
  ruby193-rubygem-netaddr \
  ruby193-rubygem-net-dns \
  ruby193-rubygem-net-scp \
  ruby193-rubygem-net-sftp \
  ruby193-rubygem-net-ssh \
  ruby193-rubygem-net-ssh-gateway \
  ruby193-rubygem-nokogiri \
  ruby193-rubygem-open4 \
  ruby193-rubygem-orm_adapter \
  ruby193-rubygem-pdfkit \
  ruby193-rubygem-Platform \
  ruby193-rubygem-polyglot \
  ruby193-rubygem-POpen4 \
  ruby193-rubygem-rack \
  ruby193-rubygem-rack-cache \
  ruby193-rubygem-rack-mount \
  ruby193-rubygem-rack-ssl \
  ruby193-rubygem-rack-test \
  ruby193-rubygem-rails \
  ruby193-rubygem-rails_4_session_flash_backport \
  ruby193-rubygem-railties \
  ruby193-rubygem-rake \
  ruby193-rubygem-rdoc \
  ruby193-rubygem-RedCloth \
  ruby193-rubygem-request_store \
  ruby193-rubygem-rspec \
  ruby193-rubygem-rspec-core \
  ruby193-rubygem-rspec-expectations \
  ruby193-rubygem-rspec-mocks \
  ruby193-rubygem-rspec-rails \
  ruby193-rubygem-rubycas-client \
  ruby193-rubygem-rubygems-bundler \
  ruby193-rubygem-ruby-graphviz \
  ruby193-rubygem-rubyzip \
  ruby193-rubygem-rvm \
  ruby193-rubygems \
  ruby193-rubygems-devel \
  ruby193-rubygem-selenium-webdriver \
  ruby193-rubygem-simple_form \
  ruby193-rubygem-sprockets \
  ruby193-rubygem-stringex \
  ruby193-rubygem-thin \
  ruby193-rubygem-thor \
  ruby193-rubygem-tilt \
  ruby193-rubygem-timezone_local \
  ruby193-rubygem-treetop \
  ruby193-rubygem-turn \
  ruby193-rubygem-tzinfo \
  ruby193-rubygem-uuidtools \
  ruby193-rubygem-warden \
  ruby193-rubygem-websocket \
  ruby193-rubygem-whois \
  ruby193-rubygem-xpath \
  ruby193-rubygem-yui-compressor \
  ruby193-ruby-irb \
  ruby193-ruby-libs \
  ruby193-ruby-tcltk \
  ruby193-rubygem-delayed_job_data_mapper \
  ruby193-rubygem-dm-is-read_only \
  ruby193-rubygem-devise_cas_authenticatable \
  ruby193-rubygem-ezprint-doc

# Copy yum configuration and locally built packages (to avoid need of temporary web-server to deploy packages).
COPY dockerfiles/etc/yum.repos.d/bpac-local.repo /etc/yum.repos.d/
COPY dockerfiles/var/lib/bpac-yum-repo/* /var/lib/bpac-yum-repo/
WORKDIR /var/lib/bpac-yum-repo/
RUN createrepo_c .

# Install out packages from local repository
RUN yum install -y \
  bpac-bricata-workers \
  bpac-httpd-conf \
  bpac-container-init

# Run systemd by default via init.sh script, to start required services
CMD ["/usr/bin/bpac-container-init.sh"]
