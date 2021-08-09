add_executable(Ransomeware App.config
Form1.cs
Form1.Designer.cs
Form1.resx
Main.cs

Properties/AssemblyInfo.cs
Properties/Resources.Designer.cs
Properties/Resources.resx
Properties/Settings.Designer.cs
Properties/Settings.settings)

csharp_set_designer_cs_properties(
Properties/AssemblyInfo.cs
Properties/Resources.Designer.cs
Properties/Resources.resx
Properties/Settings.Designer.cs
Properties/Settings.settings)

set_property(TARGET ${PROJECT_NAME} PROPERTY WIN32_EXECUTABLE TRUE)

# Set the C# language version (defaults to 3.0).

set_property(TARGET ${PROJECT_NAME} PROPERTY 
    VS_DOTNET_REFERENCE_AES "${CMAKE_BINARY_DIR}/AES/Debug/AES.dll")
# Set the source file properties for Windows Forms use.
message("${CMAKE_BINARY_DIR}/AES/Debug/AES.dll")
csharp_set_windows_forms_properties(
Form1.cs
Form1.Designer.cs
Form1.resx

Properties/AssemblyInfo.cs
Properties/Resources.Designer.cs
Properties/Resources.resx
Properties/Settings.Designer.cs
Properties/Settings.settings
)
# Add in the .NET reference libraries.
set_property(TARGET ${PROJECT_NAME} PROPERTY VS_DOTNET_REFERENCES
" Microsoft.Win32"
 "System"
 "AES"
 "AES.AES"
 "System.Data"
 "System.Diagnostics"
 "System.Drawing"
 "System.IO"
 "System.Runtime.InteropServices"
 "System.Security.Cryptography"
 "System.Text"
 "System.Windows.Forms"
)

