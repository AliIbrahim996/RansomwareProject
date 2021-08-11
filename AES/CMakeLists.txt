project(AES)
# Define the DLL target, including all relevant project files.
add_library(AES SHARED Cipher.cs AES.cs StringParser.cs)


set_property(TARGET AES PROPERTY WIN32_EXECUTABLE TRUE)


# Add in some .NET reference libraries.
set_property(TARGET AES PROPERTY VS_DOTNET_REFERENCES
    "System"
    "System.Text"
    "System.IO"
)