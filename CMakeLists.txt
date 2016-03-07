cmake_minimum_required(VERSION 3.3)
project(mod_defender)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_OUTPUT_NAME "")

<<<<<<< HEAD
include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES mod_defender.cpp mod_defender.hpp CApplication.cpp CApplication.hpp)
=======
include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include/apr-1 /usr/include /usr/local/include/apr-1/
        /usr/local/include/ /usr/local/include/apache24)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g")

set(SOURCE_FILES mod_defender.cpp mod_defender.hpp CApplication.cpp CApplication.hpp libinjection/libinjection.h
        libinjection/libinjection_html5.c libinjection/libinjection_sqli.c libinjection/libinjection_sqli.h
        libinjection/libinjection_sqli_data.h libinjection/libinjection_xss.c libinjection/libinjection_xss.h
<<<<<<< HEAD
        RuleParser.cpp RuleParser.h Util.cpp Util.h)
>>>>>>> 5eee329... naxsi core rules parser
=======
        NxParser.cpp NxParser.h Util.cpp Util.h)
>>>>>>> 90f8163... per-directory config handler
add_library(mod_defender SHARED ${SOURCE_FILES})

add_custom_command(
    OUTPUT stamped_file.lic
    COMMAND LicenseStamper any other arguments

    VERBATIM
)

ADD_CUSTOM_COMMAND(
        TARGET mod_defender
        POST_BUILD
        COMMAND sudo apxs -n defender -i ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_defender.so
        COMMAND sudo service apache2 restart
        COMMENT "Running APXS then reloading Apache"
)