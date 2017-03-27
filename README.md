# Mod Defender
Mod Defender is an Apache2 module aiming to block attacks thanks to a whitelisting policy

## Dependencies
* apache2-dev package to provide Apache Extension Tool and Apache2 headers
* gcc & g++ >= 5.2
* make
* cmake >= 3.2

## Installation
### Debian
1. Install dependencies
	```sh
	sudo apt-get install apache2-dev
	```

1. Compile the source
	```sh
	cmake .
	make -j 4
	```

1. Use Apache Extension Tool to install the module
    ```sh
    sudo apxs -n defender -i lib/mod_defender.so
    ```

1. Create its module load file for Apache2
	```sh
    echo "LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so" | sudo tee \
    /etc/apache2/mods-available/defender.load > /dev/null
	```

1. Add `Include /etc/moddefender/*.conf` in the desired section of your virtual host config

1. Create Mod Defender conf directory
    ```sh
    sudo mkdir -p /etc/moddefender/
    ```

1. Populate it with conf
	```sh
	sudo wget -O /etc/moddefender/core_rules.conf \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```
    ```sh
    cat << EOF | sudo tee /etc/moddefender/moddefender.conf > /dev/null
    # Match log path
    MatchLog \${APACHE_LOG_DIR}/moddef_match.log
    # JSON Match log path
    JSONMatchLog /var/log/moddef_json_match.log
    # Request body limit
    RequestBodyLimit 131072
    # Learning mode toggle
    LearningMode On
    # Extensive Learning log toggle
    ExtensiveLog Off
    # Libinjection SQL toggle
    LibinjectionSQL Off
    # Libinjection XSS toggle
    LibinjectionXSS Off
    ## Score action
    CheckRule "\$SQL >= 8" BLOCK
    CheckRule "\$RFI >= 8" BLOCK
    CheckRule "\$TRAVERSAL >= 4" BLOCK
    CheckRule "\$EVADE >= 4" BLOCK
    CheckRule "\$XSS >= 8" BLOCK
    EOF
    ```

1. Enable the module with apache2
	```sh
	sudo a2enmod defender
	```

1. Reload Apache2 to take effect
	```sh
	sudo service apache2 restart
	```

### FreeBSD
1. Install dependencies
	```sh
	pkg install apr gcc cmake
	```

1. Compile the source
	```sh
	cmake .
	make -j 4
	```

1. Create its module load file for Apache2
   	```sh
    cat << EOF | tee /usr/local/etc/apache24/modules.d/250_mod_defender.conf > /dev/null
    LoadModule defender_module libexec/apache24/mod_defender.so
    <IfModule defender_module>
    Include etc/moddefender/*.conf
    </IfModule>
    EOF
   	```

1. Create Mod Defender conf directory
    ```sh
    mkdir -p /usr/local/etc/moddefender/
    ```

1. Populate it with conf
	```sh
	wget -O /usr/local/etc/moddefender/core_rules.conf \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```
    ```sh
    cat << EOF | tee /usr/local/etc/moddefender/moddefender.conf > /dev/null
    # Match log path
    MatchLog /var/log/moddef_match.log
    # JSON Match log path
    JSONMatchLog /var/log/moddef_json_match.log
    # Request body limit
    RequestBodyLimit 131072
    # Learning mode toggle
    LearningMode On
    # Extensive Learning log toggle
    ExtensiveLog Off
    # Libinjection SQL toggle
    LibinjectionSQL Off
    # Libinjection XSS toggle
    LibinjectionXSS Off
    ## Score action
    CheckRule "\$SQL >= 8" BLOCK
    CheckRule "\$RFI >= 8" BLOCK
    CheckRule "\$TRAVERSAL >= 4" BLOCK
    CheckRule "\$EVADE >= 4" BLOCK
    CheckRule "\$XSS >= 8" BLOCK
    EOF
    ```

1. Reload Apache2 to take effect
	```sh
	service apache24 restart
	```