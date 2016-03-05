# Mod Defender
Mod Defender is an Apache2 module aiming to block attacks thanks to a whitelisting policy

### Dependencies
* apache2-dev package to provide APXS and Apache2 headers
* gcc & g++ >= 5.2
* CMake >= 3.2

### Installation
1. You need apache2-dev package installed	
	```sh
	$ sudo apt-get install apache2-dev
	```

2. Compile the source	
	```sh
	$ cmake .
	$ make 
	```

3. Use APXS to install the module	
	```sh
	$ sudo apxs -n defender -i lib/mod_defender.so
	```

4. Create its module load file for Apache2	
	```sh
	$ sudo echo "LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so" > \
	$ /etc/apache2/mods-available/defender.load  
	```
5. Create its module conf file for Apache2

    ```sh
	$ sudo nano "LoadModule defender_module /etc/apache2/mods-available/defender.conf" > \
    <IfModule security2_module>
        IncludeOptional /etc/moddefender/*.conf
    </IfModule>
	```

6. Enable the module with apache2
	```sh
	$ sudo a2enmod defender  
	```

7. Reload Apache2 to take effect
	```sh
	$ sudo service apache2 restart
	```