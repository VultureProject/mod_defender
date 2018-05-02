#!/bin/bash

set -e

sudo mkdir /etc/apache2/ssl
sudo cp tests/cert/apache.crt /etc/apache2/ssl
sudo cp tests/cert/apache.key /etc/apache2/ssl

sudo mkdir /etc/defender/
sudo wget -O /etc/defender/core.rules https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
sudo sed -i "s/select|union|update|delete|insert|table|from|ascii|hex|unhex|drop/\\\b(select|union|update|delete|insert|table|from|ascii|hex|unhex|drop)\\\b/" /etc/defender/core.rules

printf \
    "LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so
      <IfModule defender_module>
      Include /etc/defender/core.rules
      </IfModule>" | sudo tee /etc/apache2/mods-available/defender.load

sudo apachectl -v
sudo apachectl -M
sudo a2enmod ssl
sudo a2enmod defender
sudo service apache2 stop

printf \
    "<IfModule mod_ssl.c>
    <VirtualHost localhost:443>
        LogLevel notice
        AllowEncodedSlashes On
        ErrorLog \${APACHE_LOG_DIR}/error.log
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl/apache.crt
        SSLCertificateKeyFile /etc/apache2/ssl/apache.key
        <Location />
            <IfModule defender_module>
                Defender On
                MatchLog \${APACHE_LOG_DIR}/defender_match.log
                JSONMatchLog \${APACHE_LOG_DIR}/defender_json_match.log
                RequestBodyLimit 8388608
                LearningMode Off
                ExtensiveLog Off
                LibinjectionSQL Off
                LibinjectionXSS Off
                CheckRule \"\$SQL >= 8\" BLOCK
                CheckRule \"\$RFI >= 8\" BLOCK
                CheckRule \"\$TRAVERSAL >= 4\" BLOCK
                CheckRule \"\$EVADE >= 4\" BLOCK
                CheckRule \"\$XSS >= 8\" BLOCK
                CheckRule \"\$UPLOAD >= 8\" BLOCK
            </IfModule>
        </Location>
    </VirtualHost>
</IfModule>" | sudo tee /etc/apache2/sites-available/ssl-default.conf

cmake -H. -Bbuild
cmake --build build
sudo cp build/mod_defender.so /usr/lib/apache2/modules/
sudo service apache2 start
cd tests/
bash core_https.sh localhost
bash internal_https.sh localhost