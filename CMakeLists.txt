cmake_minimum_required(VERSION 3.2)
project(mod_defender)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_OUTPUT_NAME "")

include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include/apr-1 /usr/include /usr/local/include/apr-1/
        /usr/local/include/ /usr/local/include/apache24)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g")

set(SOURCE_FILES mod_defender.cpp mod_defender.hpp CApplication.cpp CApplication.hpp libinjection/libinjection.h
        libinjection/libinjection_html5.c libinjection/libinjection_sqli.c libinjection/libinjection_sqli.h
        libinjection/libinjection_sqli_data.h libinjection/libinjection_xss.c libinjection/libinjection_xss.h
        NxParser.cpp NxParser.h Util.cpp Util.h)
add_library(mod_defender SHARED ${SOURCE_FILES})

add_custom_command(
        TARGET mod_defender
        POST_BUILD
        COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/lib/sudo_pass | sudo -S apxs -n defender -i ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_defender.so
        COMMAND sudo service apache2 restart
        COMMENT "Running APXS then reloading Apache"
)