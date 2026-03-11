# ─── IPAM Light v1.6.0 ───────────────────────────────────────────────────────
FROM php:8.2-fpm-alpine

# ─── DÉPENDANCES SYSTÈME ─────────────────────────────────────────────────────
RUN apk add --no-cache \
    sqlite-dev \
    libsodium-dev \
    curl \
    unzip \
    git

# ─── EXTENSIONS PHP ──────────────────────────────────────────────────────────
RUN docker-php-ext-install \
    pdo_sqlite \
    sodium

# ─── COMPOSER ────────────────────────────────────────────────────────────────
COPY --from=composer:2.7 /usr/bin/composer /usr/bin/composer

# ─── DOSSIER DE TRAVAIL ──────────────────────────────────────────────────────
WORKDIR /var/www/html

# ─── INSTALLER LES DÉPENDANCES COMPOSER ──────────────────────────────────────
COPY www/composer.json ./
RUN composer install --no-dev --optimize-autoloader --no-interaction

# ─── ROUTER PHP BUILT-IN ─────────────────────────────────────────────────────
# Bloque l'accès direct aux fichiers sensibles (équivalent .htaccess pour php -S)
COPY docker/router.php /var/www/router.php

# ─── PORT ────────────────────────────────────────────────────────────────────
EXPOSE 80

# ─── LANCEMENT avec router ───────────────────────────────────────────────────
CMD ["php", "-S", "0.0.0.0:80", "-t", "/var/www/html", "/var/www/router.php"]
