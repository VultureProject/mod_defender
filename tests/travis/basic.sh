#!/bin/sh

set -e

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
sudo a2enmod defender
sudo service apache2 stop

printf \
    "<VirtualHost *:80>
      LogLevel notice
      ErrorLog \${APACHE_LOG_DIR}/error.log
      AllowEncodedSlashes On
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
    </VirtualHost>" | sudo tee /etc/apache2/sites-available/000-default.conf

cmake -H. -Bbuild
cmake --build build
sudo cp build/mod_defender.so /usr/lib/apache2/modules/
sudo service apache2 start
cd tests/
bash core.sh localhost
bash internal.sh localhost