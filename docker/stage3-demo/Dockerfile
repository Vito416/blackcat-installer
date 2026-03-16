FROM php:8.3-cli AS vendor

WORKDIR /build

RUN apt-get update \
  && apt-get install -y --no-install-recommends git unzip ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

COPY blackcat-core /workspace/blackcat-core
COPY blackcat-config /workspace/blackcat-config

RUN mkdir -p /build/app
WORKDIR /build/app

RUN cat > composer.json <<'JSON'
{
  "name": "blackcatacademy/blackcat-stage3-demo-build",
  "type": "project",
  "license": "proprietary",
  "require": {
    "blackcatacademy/blackcat-core": "dev-main",
    "blackcatacademy/blackcat-config": "dev-main"
  },
  "repositories": [
    { "type": "path", "url": "/workspace/blackcat-core", "options": { "symlink": false } },
    { "type": "path", "url": "/workspace/blackcat-config", "options": { "symlink": false } }
  ],
  "config": {
    "optimize-autoloader": true,
    "sort-packages": true
  },
  "minimum-stability": "dev",
  "prefer-stable": true
}
JSON

RUN composer install --no-dev --optimize-autoloader --classmap-authoritative --no-interaction

FROM php:8.3-apache

RUN a2enmod rewrite ssl headers
RUN a2ensite default-ssl

COPY blackcat-installer/docker/stage3-demo/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY blackcat-installer/docker/stage3-demo/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf

# Demo hardening (applies to Apache SAPI; keeps Stage 3 strict preflight green by default).
# Note: `disable_functions` cannot be reliably set per-vhost, so we set it here at the PHP_INI_SYSTEM level.
RUN { \
    echo "display_errors=0"; \
    echo "display_startup_errors=0"; \
    echo "log_errors=1"; \
    echo "enable_dl=0"; \
    echo "open_basedir=/srv/bundle:/tmp:/etc/ssl/certs:/etc/ssl"; \
    echo "disable_functions=exec,shell_exec,system,passthru,popen,proc_open,pcntl_exec"; \
  } > /usr/local/etc/php/conf.d/blackcat-demo-hardening.ini

RUN mkdir -p /etc/ssl/private \
  && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -subj "/CN=localhost" \
    -keyout /etc/ssl/private/blackcat-demo.key \
    -out /etc/ssl/certs/blackcat-demo.crt

WORKDIR /srv/bundle

COPY blackcat-installer/templates/kernel-minimal/site /srv/bundle/site
COPY --from=vendor /build/app/vendor /srv/bundle/site/vendor

# Filesystem hardening:
# - integrity root (site/) is read-only
# - mutable state (.blackcat/) is writable by www-data
# - config.runtime.json is written at bundle root (writable by www-data via group)
RUN mkdir -p /srv/bundle/.blackcat \
  && chown -R root:root /srv/bundle/site \
  && chmod -R a-w /srv/bundle/site \
  && chown -R www-data:www-data /srv/bundle/.blackcat \
  && chmod 0700 /srv/bundle/.blackcat \
  && chown root:www-data /srv/bundle \
  && chmod 0770 /srv/bundle

EXPOSE 80 443
