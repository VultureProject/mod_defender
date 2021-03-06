#!/bin/bash

set -e

sudo mkdir /etc/apache2/ssl
cd /etc/apache2/ssl
# Create the PKI used by Apache (https tests)
sudo openssl genrsa -out ca.key 4096
echo -e "FR\nNord\nLille\nVultureProject\nTravis tests\nAC_racine\nsupport@vultureproject.org\n\n" | sudo openssl req -sha256 -new -x509 -key ./ca.key -out ./ca.crt
sudo openssl genrsa -out localhost.key 4096
echo -e "FR\nNord\nLille\nVultureProject\nTravis tests\nlocalhost\nsupport@vultureproject.org\n\n" | sudo openssl req -sha256 -new -key ./localhost.key -out ./localhost.csr
sudo openssl x509 -req -sha256 -days 1 -in ./localhost.csr -CA ./ca.crt -CAkey ./ca.key -CAcreateserial -out ./localhost.crt


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
        ServerName localhost
        LogLevel notice
        AllowEncodedSlashes On
        ErrorLog \${APACHE_LOG_DIR}/error.log
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl/localhost.crt
        SSLCertificateKeyFile /etc/apache2/ssl/localhost.key
        SSLCACertificateFile /etc/apache2/ssl/ca.crt
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

sudo a2ensite ssl-default
cd $DEFENDER_HOME
cmake -H. -Bbuild
cmake --build build
sudo cp build/mod_defender.so /usr/lib/apache2/modules/
sudo service apache2 start
cd tests/
bash core_https.sh localhost
bash internal_https.sh localhost