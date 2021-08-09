cmake_minimum_required(VERSION 3.20)
project(Ransomeware VERSION 1.0  LANGUAGES CSharp)

include(CSharpUtilities)
set(CMAKE_CSharp_FLAGS "/langversion:latest")
add_subdirectory(AES)

add_subdirectory(Dropper)

add_subdirectory(UI)