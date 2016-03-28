file(WRITE defender.load "LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so")
file(WRITE defender.conf "<IfModule defender_module>
    Include /etc/moddefender/*.conf
</IfModule>")
file(DOWNLOAD https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules ${CMAKE_BINARY_DIR}/core_rules.conf)