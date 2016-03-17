# Mod Defender
Mod Defender is an Apache2 module aiming to block attacks thanks to a whitelisting policy

### Dependencies
* apache2-dev package to provide Apache Extension Tool and Apache2 headers
* gcc & g++ >= 5.2
* CMake >= 3.2

### Installation
1. You need apache2-dev package installed	
	```sh
	$ sudo apt-get install apache2-dev
	```

1. Compile the source
	```sh
	$ cmake .
	$ make 
	```

1. Use Apache Extension Tool to install the module
	```sh
	$ sudo apxs -n defender -i lib/mod_defender.so
	```

1. Create its module load file for Apache2
	```sh
	$ sudo echo "LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so" > \
	/etc/apache2/mods-available/defender.load
	```

1. Create its module conf file for Apache2
	```sh
    $ cat <<EOT | sudo tee /etc/apache2/mods-available/defender.conf > /dev/null
    <IfModule defender_module>
        IncludeOptional /etc/moddefender/*.conf
    </IfModule>
    EOT
    ```

1. Create Mod Defender conf directory
    ```sh
    $ sudo mkdir -p /etc/moddefender/
    ```

1. Populate it with conf
	```sh
	$ sudo wget -O /etc/moddefender/core_mainrules.conf \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```
    ```sh
	$ cat <<EOT | sudo tee /etc/moddefender/checkrules.conf > /dev/null
    ## check rules
    CheckRule "\$SQL >= 8" BLOCK;
    CheckRule "\$RFI >= 8" BLOCK;
    CheckRule "\$TRAVERSAL >= 4" BLOCK;
    CheckRule "\$EVADE >= 4" BLOCK;
    CheckRule "\$XSS >= 8" BLOCK;
    EOT
    ```
    ```sh
    $ cat <<EOT | sudo tee /etc/moddefender/moddefender.conf > /dev/null
    # Match log path
    MatchLog \${APACHE_LOG_DIR}/moddef_match.log
    #Learning mode toggle
    LearningMode 1
    #SecRules mode toggle
    SecRules 1
    EOT
    ```

1. Enable the module with apache2
	```sh
	$ sudo a2enmod defender  
	```

1. Reload Apache2 to take effect
	```sh
	$ sudo service apache2 restart
	```