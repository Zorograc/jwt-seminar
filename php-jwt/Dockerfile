FROM php:8.2-cli
WORKDIR /app
RUN apt-get update && apt-get install -y unzip curl
RUN curl -sS https://getcomposer.org/installer | php && mv composer.phar /usr/local/bin/composer
COPY composer.json .
RUN composer install --ignore-platform-reqs --no-security-blocking
COPY index.php .
CMD ["php", "-S", "0.0.0.0:8080", "index.php"]