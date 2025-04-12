#!/bin/bash

# Start MySQL service
echo "Starting MySQL..."
service mysql start

# Wait for MySQL to be ready
echo "Waiting for MySQL to be ready..."
until mysqladmin ping -h "localhost" --silent; do
  sleep 1
done

# Create DB and user
mysql -u root -p$MYSQL_ROOT_PASSWORD <<EOF
CREATE DATABASE IF NOT EXISTS $MYSQL_DATABASE;
GRANT ALL PRIVILEGES ON $MYSQL_DATABASE.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
EOF


# Start Flask server
echo "Starting Flask app..."
flask run --host=0.0.0.0
