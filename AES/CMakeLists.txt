# Define the DLL target, including all relevant project files.
add_library(AESLIB SHARED AES.cs StringParser.cs)


set_property(TARGET AESLIB PROPERTY WIN32_EXECUTABLE TRUE)


# Add in some .NET reference libraries.
set_property(TARGET AESLIB PROPERTY VS_DOTNET_REFERENCES
    "System"
    "System.Collections.Generic"
    "System.Linq"
    "System.Text"
    "System.Drawing"
    "System.Threading.Tasks"
    "System.Text.RegularExpressions"
    "System.IO"
)