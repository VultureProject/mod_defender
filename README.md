# Mod Defender
Mod Defender is an Apache2 module aiming to block attacks thanks to a whitelist policy  
It uses the same format as NAXSI configs and thus is fully compatible with NXAPI  

 - Input
    - MainRule
    - BasicRule
    - CheckRule
 - Output
    - Learning log
    - Extensive learning log

## Dependencies
* apache dev package to provide APache eXtenSion Tool
* apr package to provide Apache Portal Runtime library
* gcc & g++ >= 4.9
* make
* cmake >= 3.2

## Installation
### Debian
1. Install dependencies
	```sh
	sudo apt-get install apache2-dev make gcc g++ cmake
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

1. Create its module load file
    ```sh
    cat << EOF | sudo tee /etc/apache2/mods-available/defender.load > /dev/null
    LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so
    <IfModule defender_module>
    Include /etc/moddefender/core/rules.conf
    </IfModule>
    EOF
    ```

1. Add mod_defender settings in the desired virtual host
    ```sh
    <IfModule defender_module>
    Include /etc/moddefender/*.conf
    </IfModule>
    ```

1. Create Mod Defender conf directory
    ```sh
    sudo mkdir -p /etc/moddefender/core/
    ```

1. Populate it with conf
	```sh
	sudo wget -O /etc/moddefender/core/rules.conf \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```
    ```sh
    cat << EOF | sudo tee /etc/moddefender/defender.conf > /dev/null
    # Defender toggle
    Defender On
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

1. Restart Apache2 to take effect
	```sh
	sudo service apache2 restart
	```

### FreeBSD
1. Install dependencies
	```sh
	pkg install apr make gcc cmake
	```

1. Compile the source
	```sh
	cmake .
	make -j 4
	```

1. Create its module load file
   	```sh
    cat << EOF | tee /usr/local/etc/apache24/modules.d/250_mod_defender.conf > /dev/null
    LoadModule defender_module libexec/apache24/mod_defender.so
    <IfModule defender_module>
    Include etc/moddefender/core/rules.conf
    </IfModule>
    EOF
   	```

1. Add mod_defender settings in the desired virtual host
    ```sh
    <IfModule defender_module>
    Include etc/moddefender/*.conf
    </IfModule>
    ```

1. Create Mod Defender conf directory
    ```sh
    mkdir -p /usr/local/etc/moddefender/core/
    ```

1. Populate it with conf
	```sh
	wget -O /usr/local/etc/moddefender/core/rules.conf \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```
    ```sh
    cat << EOF | tee /usr/local/etc/moddefender/defender.conf > /dev/null
    # Defender toggle
    Defender On
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

1. Restart Apache2 to take effect
	```sh
	service apache24 restart
	```

## Configuration hierarchy
### Top (apache2.conf on Debian or httpd.conf on FreeBSD)
```
# MainRule(s)
Include /etc/moddefender/core/rules.conf
```

### &lt;VirtualHost&gt; blocks (000-default.conf on Debian or httpd.conf on FreeBSD)
```
# CheckRule(s)
Include /etc/moddefender/defender.conf
# BasicRule(s)
Include /etc/moddefender/wordpress.conf
```