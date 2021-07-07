cmake_minimum_required(VERSION 3.20)
project(Ransomeware VERSION 1.0  LANGUAGES CSharp)

include(CSharpUtilities)

add_executable(main lancher.cs)

set_property(TARGET main PROPERTY VS_DOTNET_REFERENCES
    "System"
    "System.Net"
    "System.ComponentModel"
    "System.Data"
)