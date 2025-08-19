<#
.SYNOPSIS
    Setup script for Microsoft Graph Admin Console
.DESCRIPTION
    This script installs the required Microsoft Graph PowerShell modules
    and verifies the setup for the Graph Admin Console.
.AUTHOR
    PowerShell Graph Admin Console
.VERSION
    2.0.0
#>

param(
    [switch]$Force,
    [switch]$AllUsers
)

Write-Host "Microsoft Graph Admin Console - Setup Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

Write-Host "PowerShell version check passed ($($PSVersionTable.PSVersion))" -ForegroundColor Green

# Required modules for admin console
$RequiredModules = @(
    @{Name = "Microsoft.Graph.Authentication"; MinVersion = "1.0.0"},
    @{Name = "Microsoft.Graph.Users"; MinVersion = "1.0.0"},
    @{Name = "Microsoft.Graph.Groups"; MinVersion = "1.0.0"},
    @{Name = "Microsoft.Graph.DeviceManagement"; MinVersion = "1.0.0"},
    @{Name = "Microsoft.Graph.Identity.SignIns"; MinVersion = "1.0.0"},
    @{Name = "ExchangeOnlineManagement"; MinVersion = "3.0.0"},
    @{Name = "MSAL.PS"; MinVersion = "4.0.0"}
)

# Determine scope
$Scope = if ($AllUsers) { "AllUsers" } else { "CurrentUser" }
Write-Host "Installing modules for scope: $Scope" -ForegroundColor Yellow

# Check and install modules
foreach ($Module in $RequiredModules) {
    Write-Host "Checking module: $($Module.Name)..." -NoNewline
    
    $InstalledModule = Get-Module -ListAvailable -Name $Module.Name | Sort-Object Version -Descending | Select-Object -First 1
    
    if ($InstalledModule -and $InstalledModule.Version -ge [Version]$Module.MinVersion -and -not $Force) {
        Write-Host " Already installed (v$($InstalledModule.Version))" -ForegroundColor Green
    }
    else {
        Write-Host " Installing..." -ForegroundColor Yellow
        try {
            if ($Force -and $InstalledModule) {
                Write-Host "    Updating existing module..." -ForegroundColor Yellow
                Update-Module -Name $Module.Name -Scope $Scope -Force
            }
            else {
                Install-Module -Name $Module.Name -Scope $Scope -Force -AllowClobber
            }
            Write-Host "    Successfully installed $($Module.Name)" -ForegroundColor Green
        }
        catch {
            Write-Error "    Failed to install $($Module.Name): $($_.Exception.Message)"
            exit 1
        }
    }
}

Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Yellow

# Verify all modules can be imported
$AllModulesOK = $true
foreach ($Module in $RequiredModules) {
    try {
        Import-Module $Module.Name -Force -ErrorAction Stop
        Write-Host "$($Module.Name) imported successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to import $($Module.Name): $($_.Exception.Message)" -ForegroundColor Red
        $AllModulesOK = $false
    }
}

Write-Host ""

if ($AllModulesOK) {
    Write-Host "Setup completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Run the application: .\GraphApp.ps1" -ForegroundColor White
    Write-Host "2. Click 'Connect' to authenticate with Microsoft Graph" -ForegroundColor White
    Write-Host "3. Grant the required permissions when prompted" -ForegroundColor White
    Write-Host ""
    Write-Host "Required permissions for admin functions:" -ForegroundColor Yellow
    Write-Host "- User.Read.All (to read all user profiles)" -ForegroundColor White
    Write-Host "- Group.Read.All (to read all groups)" -ForegroundColor White
    Write-Host "- Organization.Read.All (to read tenant information)" -ForegroundColor White
    Write-Host "- Directory.Read.All (to read directory data)" -ForegroundColor White
    Write-Host "- DeviceManagementManagedDevices.Read.All (to read Intune devices)" -ForegroundColor White
    Write-Host "- Exchange.ManageAsApp (for Exchange Online access)" -ForegroundColor White
    Write-Host "- https://management.azure.com/.default (for Azure access)" -ForegroundColor White
}
else {
    Write-Host "Setup failed. Please check the errors above and try again." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "For more information, see README.md" -ForegroundColor Cyan
