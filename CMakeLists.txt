cmake_minimum_required(VERSION 3.20)
project(Ransomeware VERSION 1.0  LANGUAGES CSharp)

include(CSharpUtilities)

add_subdirectory(AES)

add_subdirectory(Dropper)