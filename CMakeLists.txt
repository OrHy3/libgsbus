cmake_minimum_required(VERSION 3.31)

project(libgsbus VERSION 0.3)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)

set(SOURCES src/gsbus.c)
set(HEADERS include/gsbus.h)

include_directories(${DBUS_INCLUDE_DIRS} include)

add_library(gsbus ${SOURCES})

set(CMAKE_INSTALL_PREFIX /usr)

install(TARGETS gsbus
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)

install(FILES ${HEADERS} DESTINATION include)
