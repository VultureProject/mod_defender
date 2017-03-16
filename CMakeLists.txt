cmake_minimum_required(VERSION 3.2)
project(mod_defender)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_OUTPUT_NAME "")

include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include/apr-1 /usr/include /usr/local/include/apr-1/
        /usr/local/include/ /usr/local/include/apache24)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

file(GLOB SOURCE_FILES *.cpp libinjection/*.c)
add_library(mod_defender SHARED ${SOURCE_FILES})

set(STOP_APACHE_CMD sudo systemctl stop apache2)
set(START_APACHE_CMD sudo systemctl start apache2)

set(DEF_DIR /etc/moddefender)
set(AP_MODS_AV /etc/apache2/mods-available)
set(AP_MODS_DIR /usr/lib/apache2/modules)

add_custom_command(
        TARGET mod_defender
        POST_BUILD
        COMMAND ${STOP_APACHE_CMD}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_defender.so ${AP_MODS_DIR}
        COMMAND ${START_APACHE_CMD}
        COMMENT "Copying module then restarting Apache")

install(SCRIPT "${CMAKE_SOURCE_DIR}/Install.cmake")
install(FILES ${CMAKE_BINARY_DIR}/defender.conf DESTINATION ${AP_MODS_AV})
install(FILES ${CMAKE_BINARY_DIR}/defender.load DESTINATION ${AP_MODS_AV})
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${DEF_DIR})")
install(FILES ${CMAKE_BINARY_DIR}/core_rules.conf DESTINATION ${DEF_DIR})
install(FILES ${CMAKE_SOURCE_DIR}/conf/moddefender.conf DESTINATION ${DEF_DIR})
#install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_defender.so DESTINATION ${AP_MODS_DIR})s
install(CODE "execute_process(COMMAND apxs -n defender -i ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_defender.so)")
install(CODE "execute_process(COMMAND a2enmod defender)")
install(CODE "execute_process(COMMAND ${RELOAD_APACHE_CMD})")

add_custom_target(uninstall
        COMMAND ${STOP_APACHE_CMD}
        COMMAND xargs rm < install_manifest.txt
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEF_DIR}
        COMMAND a2dismod defender
        COMMAND ${START_APACHE_CMD}
        COMMENT "Uninstalling... Removing files, disabling module then restarting Apache")
