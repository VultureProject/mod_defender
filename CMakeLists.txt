cmake_minimum_required(VERSION 3.2)
project(mod_defender)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_SHARED_LIBRARY_PREFIX "")

include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include/apr-1 /usr/include /usr/local/include/apr-1/
        /usr/local/include/ /usr/local/include/apache24 /usr/home/vlt-sys/Engine/include/)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

file(GLOB SOURCE_FILES *.cpp libinjection/*.c)
add_library(mod_defender SHARED ${SOURCE_FILES})

if (AUTO)
    set(STOP_APACHE_CMD sudo systemctl stop apache2)
    set(START_APACHE_CMD sudo systemctl start apache2)
    set(AP_MODS_AV /etc/apache2/mods-available)
    set(AP_MODS_DIR /usr/lib/apache2/modules)
    
    if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        set(STOP_APACHE_CMD service apache24 restart)
        set(START_APACHE_CMD service apache24 restart)
        set(AP_MODS_DIR /usr/local/libexec/apache24/)

        if (EXISTS "/usr/local/etc/rc.d/vulture")
            set(STOP_APACHE_CMD "")
            set(START_APACHE_CMD "")
            set(AP_MODS_DIR /usr/home/vlt-sys/Engine/modules/)
        endif ()
    endif ()

    add_custom_command(
            TARGET mod_defender
            POST_BUILD
            COMMAND ${STOP_APACHE_CMD}
            COMMAND cp $<TARGET_FILE:mod_defender> ${AP_MODS_DIR}
            COMMAND ${START_APACHE_CMD}
            COMMENT "Copying module then restarting Apache")
endif ()
