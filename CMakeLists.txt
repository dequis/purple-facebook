cmake_minimum_required(VERSION 3.20)
project(purple_facebook)

set(CMAKE_CXX_STANDARD 14)

set(PLUGIN_VERSION 0.9.6)
set(PACKAGE_NAME purple-facebook)
set(PACKAGE_TARNAME purple-facebook)
set(PACKAGE_VERSION ${PLUGIN_VERSION})
set(PACKAGE_STRING "purple-facebook\ $(PLUGIN_VERSION)")
set(PACKAGE_BUGREPORT https://github.com/dequis/purple-facebook/issues)
set(PACKAGE_URL https://github.com/dequis/purple-facebook)
set(PACKAGE purple-facebook)
set(VERSION ${PLUGIN_VERSION})


include_directories(include)
include_directories(${CMAKE_SOURCE_DIR})
include_directories(facebook)

find_package(PkgConfig REQUIRED)
#get glib
pkg_search_module(GLIB REQUIRED glib-2.0)
include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})
#get json-glib
pkg_search_module(JSON-GLIB REQUIRED json-glib-1.0)
include_directories(${JSON-GLIB_INCLUDE_DIRS})
link_directories(${JSON-GLIB_LIBRARY_DIRS})
#get purple
pkg_search_module(PURPLE REQUIRED purple)
include_directories(${PURPLE_INCLUDE_DIRS})
link_directories(${PURPLE_LIBRARY_DIRS})
#get zlib
pkg_search_module(ZLIB REQUIRED zlib)
include_directories(${ZLIB_INCLUDE_DIRS})
link_directories(${ZLIB_LIBRARY_DIRS})

#check glib-genmarshal
find_program(GLIB_MARSHALLER glib-genmarshal)
if(NOT GLIB_MARSHALLER)
    message(FATAL_ERROR "gen-marshal not found!")
endif()

set(MARSHAL_H ${CMAKE_SOURCE_DIR}/facebook/marshal.h)
set(MARSHAL_C ${CMAKE_SOURCE_DIR}/facebook/marshal.c)

add_custom_command(
        OUTPUT ${MARSHAL_H}
        COMMAND glib-genmarshal --prefix=fb_marshal --header ${CMAKE_SOURCE_DIR}/facebook/marshaller.list >> ${MARSHAL_H}
        COMMENT "Generating marshal.h"
)

add_custom_command(
        OUTPUT ${MARSHAL_C}
        COMMAND glib-genmarshal --prefix=fb_marshal --body ${CMAKE_SOURCE_DIR}/facebook/marshaller.list >> ${MARSHAL_C}
        COMMENT "Generating marshal.c"
)


add_library(facebook SHARED
        ${MARSHAL_H}
        ${MARSHAL_C}
        facebook/api.c
        facebook/data.c
        facebook/facebook.c
        facebook/http.c
        facebook/id.h
        facebook/json.c
        facebook/mqtt.c
        facebook/thrift.c
        facebook/util.c
        purple2compat/http.c
        purple2compat/purple-socket.c
        )

add_definitions(${GLIB_CFLAGS_OTHER}
        ${JSON-GLIB_CFLAGS_OTHER}
        ${PURPLE_CFLAGS_OTHER}
        ${ZLIB_CFLAGS_OTHER}
        )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPURPLE_PLUGINS -include purple-compat.h")

add_definitions(-DPACKAGE_VERSION=\"${PACKAGE_VERSION}\")
add_definitions(-DPACKAGE_URL=\"${PACKAGE_URL}\")

target_link_libraries(facebook
        ${GLIB_LIBRARIES}
        ${JSON-GLIB_LIBRARIES}
        ${PURPLE_LIBRARIES}
        ${ZLIB_LIBRARIES})

link_directories(
        ${PURPLE_LIBRARY_DIRS}
)
