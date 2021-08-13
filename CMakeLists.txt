cmake_minimum_required(VERSION 3.20)

project(RansomewareMain VERSION 1.0  LANGUAGES CSharp)
include(CSharpUtilities)

add_subdirectory(AES)

add_subdirectory(Dropper)

add_subdirectory(UI)

IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    SET(CMAKE_INSTALL_PREFIX "C:/local" CACHE PATH "change installation dir" FORCE)
ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
install(TARGETS Ransomeware)