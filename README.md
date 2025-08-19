# Strata365

A modern PowerShell application with a sleek dark theme and glass morphism UI for Microsoft Graph administration. This application provides a comprehensive administrative interface for managing Microsoft 365 tenants with multi-tenant support.

## 🌟 Features

### Modern Dark Theme UI
- **Glass Morphism Design**: Beautiful translucent cards with subtle gradients
- **Dark Theme**: Easy on the eyes with modern color palette
- **Custom Window Chrome**: Borderless window with custom title bar
- **Responsive Layout**: Adapts to different screen sizes

### Multi-Tenant Support
- **Company Name Display**: Shows the organization name prominently in the header
- **Tenant Switching**: Easily identify which tenant you're connected to
- **Connection Status**: Clear visual indicators for authentication state

### Administrative Sections
- **🏢 Admin Overview**: Tenant information and quick statistics
- **🔐 Entra ID**: User and group management (expandable)
- **📱 Intune**: Device management and policies (expandable)
- **🛡️ Security**: Security policies and compliance (expandable)

### Real-time Statistics
- **User Count**: Total users in the organization
- **Group Count**: Total groups in the directory
- **Device Count**: Managed devices (requires Intune license)

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 with PowerShell 5.1 or later
- Microsoft Graph PowerShell modules
- Appropriate Microsoft 365 admin permissions

### Installation

1. **Clone or download** this repository
2. **Run the setup script** to install required modules:
   ```powershell
   .\Setup.ps1
   ```
3. **Launch the application**:
   ```powershell
   .\GraphApp.ps1
   ```
   Or use the batch file:
   ```cmd
   Launch.bat
   ```

### First Time Setup

1. Click the **Connect** button in the top-right corner
2. Sign in with your Microsoft 365 admin account
3. Grant the requested permissions when prompted
4. The company name will appear in the header once connected

## 🔐 Required Permissions

The application requests the following Microsoft Graph permissions:

- **User.Read.All** - Read all user profiles
- **User.ReadWrite.All** - Create and manage users
- **Group.Read.All** - Read all groups
- **Group.ReadWrite.All** - Manage group memberships
- **Organization.Read.All** - Read tenant information
- **Directory.Read.All** - Read directory data
- **Directory.ReadWrite.All** - Manage directory objects
- **DeviceManagementManagedDevices.Read.All** - Read Intune devices
- **UserAuthenticationMethod.ReadWrite.All** - Manage user MFA settings
- **Policy.Read.All** - Read security policies
- **Policy.ReadWrite.ConditionalAccess** - Read Conditional Access policies

**Note**: For accurate shared mailbox detection, the application also connects to Exchange Online PowerShell, which uses the same authentication as Microsoft Graph.

## 🎨 UI Components

### Navigation
- **Left Sidebar**: Clean navigation between different admin sections
- **Active Indicators**: Visual highlighting of the current section
- **Hover Effects**: Smooth transitions and glass morphism effects

### Header Bar
- **App Branding**: Strata365 with logo
- **Company Display**: Shows connected organization name
- **Auth Controls**: Connect/Disconnect buttons with status indicators

### Content Cards
- **Glass Morphism**: Translucent cards with subtle borders
- **Drop Shadows**: Depth and dimension with modern shadows
- **Responsive Grid**: Statistics cards that adapt to content

## 🔧 Customization

### Theme Colors
The application uses a modern dark theme with these primary colors:
- **Background**: `#1E1E1E` (Dark gray)
- **Cards**: Glass morphism with white gradients
- **Accent**: Purple gradient (`#6366F1` to `#8B5CF6`)
- **Success**: Green gradient (`#10B981` to `#059669`)
- **Danger**: Red gradient (`#EF4444` to `#DC2626`)

### Extending Functionality
Each navigation section (Entra ID, Intune, Security) is designed to be expandable:

1. Add content to the respective XAML sections
2. Implement PowerShell functions for data retrieval
3. Wire up event handlers in the main script

## 📁 File Structure

```
PowerShell-Graph-App/
├── GraphApp.ps1          # Main application script
├── MainWindow.xaml       # UI definition with dark theme
├── Setup.ps1            # Module installation script
├── Launch.bat           # Windows batch launcher
└── README.md            # This documentation
```

## 🛠️ Troubleshooting

### Common Issues

**Company name not showing:**
- Ensure you have `Organization.Read.All` permissions
- Check that you're signed in as a tenant admin
- Verify the tenant has organization information configured

**Module not found errors:**
- Run `.\Setup.ps1` to install required modules
- Use `-Force` parameter to update existing modules
- Check PowerShell execution policy

**UI not loading:**
- Ensure .NET Framework 4.5+ is installed
- Check that XAML file is in the same directory
- Verify PowerShell can load WPF assemblies

### Setup Parameters

```powershell
# Install for all users (requires admin)
.\Setup.ps1 -AllUsers

# Force update existing modules
.\Setup.ps1 -Force

# Combine parameters
.\Setup.ps1 -AllUsers -Force
```

## 🔄 Version History

### v2.0.0 (Current)
- ✨ Complete UI redesign with dark theme
- ✨ Glass morphism effects and modern styling
- ✨ Improved company name display
- ✨ Multi-tenant support enhancements
- ✨ Custom window chrome
- ✨ Enhanced error handling

### v1.0.0
- 🎉 Initial release with basic functionality
- 📊 Admin overview and statistics
- 🔐 Microsoft Graph authentication
- 📱 Navigation structure

## 📝 License

This project is provided as-is for educational and administrative purposes. Please ensure you comply with your organization's policies when using Microsoft Graph APIs.

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this administrative console.

---

**Note**: This application requires appropriate Microsoft 365 administrative permissions. Always test in a development environment before using in production.
