
add_executable(MusicApp
    App.config
    DropperGUI.cs
    DropperGUI.Designer.cs
    DropperGUI.resx
    Dropper.cs
    icons8-musical-notes-80.ico

    Properties/AssemblyInfo.cs
    Properties/Resources.Designer.cs
    Properties/Resources.resx
    Properties/Settings.Designer.cs
    Properties/app.manifest
    Properties/Settings.settings)

    csharp_set_designer_cs_properties(
    Properties/AssemblyInfo.cs
    Properties/Resources.Designer.cs
    Properties/Resources.resx
    Properties/Settings.Designer.cs
    Properties/Settings.settings)


# Set the source file properties for Windows Forms use.
csharp_set_windows_forms_properties(
    DropperGUI.cs
    DropperGUI.Designer.cs
    DropperGUI.resx
    icons8-musical-notes-80.ico

    Properties/AssemblyInfo.cs
    Properties/Resources.Designer.cs
    Properties/Resources.resx
    Properties/Settings.Designer.cs
    Properties/Settings.settings
)

# Add in the .NET reference libraries.
set_property(TARGET MusicApp PROPERTY VS_DOTNET_REFERENCES
    "System"
    "System.Core"
    "System.Collections.Generic"
    "System.ComponentModel"
    "System.Linq"
    "System.Text"
    "System.Threading.Tasks"
    "System.Net"
    "System.Diagnostics"
    "System.IO"
    "System.Data"
    "System.Drawing"
    "System.Windows.Forms"
)