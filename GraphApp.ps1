#Requires -Version 5.1

<#
.SYNOPSIS
    Strata365 - PowerShell application with WPF UI
.DESCRIPTION
    An administrative console for Microsoft Graph with navigation-based UI
    for managing Admin, Entra ID, Intune, and Security functions.
    Enhanced with MSAL.NET for proper token sharing between services.
.AUTHOR
    Chris Braeuer
.VERSION
    2.2.1
#>

# Import required assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Global variables
$Global:IsConnected = $false
$Global:IsExchangeConnected = $false
$Global:CurrentUser = $null
$Global:TenantInfo = $null
$Global:CurrentSection = "Admin"
$Global:MsalToken = $null

# Function to show error messages
function Show-ErrorMessage {
    param([string]$Message)
    [System.Windows.MessageBox]::Show($Message, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
}

# Function to show success messages
function Show-SuccessMessage {
    param([string]$Message)
    [System.Windows.MessageBox]::Show($Message, "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
}

# Function to update navigation button styles
function Update-NavigationButton {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$ActiveSection)

    if (-not $PSCmdlet.ShouldProcess("Strata365 UI","Update navigation to '$ActiveSection'")) { return }
    
    $Global:CurrentSection = $ActiveSection
    
    # Reset all buttons to normal style
    $Window.FindName("AdminButton").Style = $Window.FindResource("NavButton")
    $Window.FindName("EntraButton").Style = $Window.FindResource("NavButton")
    $Window.FindName("IntuneButton").Style = $Window.FindResource("NavButton")
    $Window.FindName("SecurityButton").Style = $Window.FindResource("NavButton")
    
    # Set active button style
    switch ($ActiveSection) {
        "Admin" { $Window.FindName("AdminButton").Style = $Window.FindResource("ActiveNavButton") }
        "Entra" { $Window.FindName("EntraButton").Style = $Window.FindResource("ActiveNavButton") }
        "Intune" { $Window.FindName("IntuneButton").Style = $Window.FindResource("ActiveNavButton") }
        "Security" { $Window.FindName("SecurityButton").Style = $Window.FindResource("ActiveNavButton") }
    }
    
    # Hide all content sections
    $Window.FindName("AdminContent").Visibility = "Collapsed"
    $Window.FindName("EntraContent").Visibility = "Collapsed"
    $Window.FindName("IntuneContent").Visibility = "Collapsed"
    $Window.FindName("SecurityContent").Visibility = "Collapsed"
    
    # Show active content section
    switch ($ActiveSection) {
        "Admin" { $Window.FindName("AdminContent").Visibility = "Visible" }
        "Entra" { $Window.FindName("EntraContent").Visibility = "Visible" }
        "Intune" { $Window.FindName("IntuneContent").Visibility = "Visible" }
        "Security" { $Window.FindName("SecurityContent").Visibility = "Visible" }
    }
}

# Enhanced Exchange Online connection function with multiple authentication methods
function Connect-ExchangeOnlineEnhanced {
    param(
        [string]$AccountId,
        [string]$TenantId
    )
    
    try {
        Write-Host "Connecting to Exchange Online with enhanced authentication..." -ForegroundColor Cyan
        
        # Check if ExchangeOnlineManagement module is available
        $ExoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $ExoModule) {
            Write-Warning "ExchangeOnlineManagement module not available. Shared mailbox detection will use Graph API fallback."
            return $false
        }
        
        Write-Host ("Found ExchangeOnlineManagement module version: {0}" -f $ExoModule.Version) -ForegroundColor Gray
        if ($TenantId) { Write-Host ("Target Tenant: {0}" -f $TenantId) -ForegroundColor Gray }
        
        # Method 1: Try connecting with UserPrincipalName (most reliable)
        if ($AccountId) {
            try {
                Write-Host "Method 1: Connecting with UserPrincipalName..." -ForegroundColor Yellow
                Connect-ExchangeOnline -UserPrincipalName $AccountId -ShowBanner:$false -ErrorAction Stop
                
                Write-Host "Exchange Online connected successfully using UserPrincipalName" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Warning "Method 1 failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Try interactive authentication
        try {
            Write-Host "Method 2: Trying interactive authentication..." -ForegroundColor Yellow
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            
            Write-Host "Exchange Online connected successfully using interactive authentication" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Method 2 failed: $($_.Exception.Message)"
        }
        
        # Method 3: Try with UseRPSSession for compatibility
        try {
            Write-Host "Method 3: Trying with UseRPSSession for compatibility..." -ForegroundColor Yellow
            if ($AccountId) {
                Connect-ExchangeOnline -UserPrincipalName $AccountId -UseRPSSession -ShowBanner:$false -ErrorAction Stop
            } else {
                Connect-ExchangeOnline -UseRPSSession -ShowBanner:$false -ErrorAction Stop
            }
            
            Write-Host "Exchange Online connected successfully using RPS session" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Method 3 failed: $($_.Exception.Message)"
        }
        
        # Method 4: Try device code authentication
        try {
            Write-Host "Method 4: Trying device code authentication..." -ForegroundColor Yellow
            Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
            
            Write-Host "Exchange Online connected successfully using device code" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Method 4 failed: $($_.Exception.Message)"
        }
        
        Write-Warning "All Exchange Online connection methods failed. Using Graph API fallback for shared mailbox detection."
        return $false
    }
    catch {
        Write-Warning "Exchange Online connection failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to test Exchange Online connection (supports REST/sessionless and RPS)
function Test-ExchangeOnlineConnection {
    try {
        # Primary: try a simple EXO cmdlet (works with REST/sessionless)
        try {
            Get-OrganizationConfig -ErrorAction Stop | Out-Null
            Write-Host "Exchange Online connectivity verified via Get-OrganizationConfig" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Primary EXO connectivity test failed: $($_.Exception.Message)"
        }

        # Secondary: try a REST-specific cmdlet
        try {
            Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
            Write-Host "Exchange Online connectivity verified via Get-EXOMailbox" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Secondary EXO connectivity test failed: $($_.Exception.Message)"
        }

        # Tertiary: detect legacy RPS session
        $ExoSession = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" -and 
            $_.State -eq "Opened" -and
            $_.ComputerName -like "*.outlook.com"
        }
        
        if ($ExoSession) {
            Write-Host ("Exchange Online RPS session detected: {0}" -f $ExoSession.ComputerName) -ForegroundColor Gray
            return $true
        } else {
            Write-Warning "No active Exchange Online connection detected"
            return $false
        }
    }
    catch {
        Write-Warning "Exchange Online connection test failed: $($_.Exception.Message)"
        return $false
    }
}

# Module bootstrap: ensure PSGallery trust and install/import required modules
function Initialize-Module {
    param([string[]]$Modules)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    try {
        if (-not (Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction SilentlyContinue
        }
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    } catch {}
    # Determine missing modules
    $missing = @()
    foreach ($m in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m }
    }
    # Install missing modules individually (no Microsoft.Graph meta module)
    if ($missing.Count -gt 0) {
        Write-Host ("Installing missing modules: {0}" -f ($missing -join ", ")) -ForegroundColor Yellow
        foreach ($m in $missing) {
            try {
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host ("Installed module: {0}" -f $m) -ForegroundColor Green
            } catch {
                Write-Warning ("Failed to install {0}: {1}" -f $m, $_.Exception.Message)
            }
        }
    }
    # Import requested modules
    foreach ($m in $Modules) {
        try { Import-Module $m -Force -ErrorAction Stop } catch { Write-Warning ("Failed to import {0}: {1}" -f $m, $_.Exception.Message) }
    }
}

# Permissions diagnostics helper
function Show-PermissionsDiagnostic {
    Write-Host "Running permissions diagnostics..." -ForegroundColor Cyan
    # Check Graph delegated scopes granted vs required
    try {
        $requiredScopes = @(
            "User.Read",
            "User.Read.All",
            "Group.Read.All",
            "Organization.Read.All",
            "Directory.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All",
            "Policy.Read.All",
            "UserAuthenticationMethod.Read.All"
        )
        $ctx = Get-MgContext
        $granted = @()
        if ($ctx -and $ctx.Scopes) { $granted = $ctx.Scopes }
        $missingScopes = @()
        foreach ($s in $requiredScopes) {
            if ($granted -notcontains $s) { $missingScopes += $s }
        }
        if ($missingScopes.Count -gt 0) {
            Write-Warning ("Missing Graph scopes (grant/admin-consent these): {0}" -f ($missingScopes -join ", "))
        } else {
            Write-Host "All required Graph scopes granted" -ForegroundColor Green
        }
    } catch {}
    # Intune device read diagnostic
    try {
        $null = Get-MgDeviceManagementManagedDevice -Top 1 -ErrorAction Stop
        Write-Host "Intune: Managed devices accessible" -ForegroundColor Green
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "Insufficient privileges") {
            Write-Warning "Intune: Access denied. Requires DeviceManagementManagedDevices.Read.All with admin consent and an Intune admin role."
        } elseif ($msg -match "license" -or $msg -match "not licensed" -or $msg -match "subscription") {
            Write-Warning "Intune: Tenant or user lacks an Intune license/subscription."
        } else {
            Write-Warning ("Intune: Managed devices query failed: {0}" -f $msg)
        }
    }
    # Graph Conditional Access policies
    try {
        $null = Get-MgIdentityConditionalAccessPolicy -Top 1 -ErrorAction Stop
        Write-Host "Graph Conditional Access: OK (Policy.Read.All granted)" -ForegroundColor Green
    } catch {
        Write-Warning "Graph Conditional Access: Access denied. Requires Policy.Read.All with admin consent and Security Reader/Administrator or Global Administrator role."
    }
    # Exchange Online basic reads
    try {
        $null = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
        Write-Host "Exchange Online: Get-EXOMailbox accessible (REST/sessionless)" -ForegroundColor Green
    } catch {
        Write-Warning "Exchange Online: Get-EXOMailbox blocked. Ensure ExchangeOnlineManagement is updated and you have Exchange roles."
    }
    try {
        $null = Get-Mailbox -ResultSize 1 -ErrorAction Stop
        Write-Host "Exchange Online: Get-Mailbox accessible" -ForegroundColor Green
    } catch {
        Write-Warning "Exchange Online: Get-Mailbox denied. Requires roles like View-Only Recipients, Recipient Management, or Exchange Administrator."
    }
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        Write-Host "Exchange Online: Organization config accessible" -ForegroundColor Green
    } catch {
        Write-Warning "Exchange Online: Organization config denied. Requires Organization Management or View-Only Organization Management."
    }
}

# Function to connect with enhanced authentication
function Connect-WithCredential {
    try {
        Write-Host "Connecting to Microsoft 365 services with enhanced authentication..." -ForegroundColor Cyan
        
        # Import required modules
        Write-Host "Importing required modules..." -ForegroundColor Yellow
        Import-Module Microsoft.Graph.Authentication -Force
        Import-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
        
        $ConnectionResults = @{
            Graph = $false
            Exchange = $false
        }
        
        # Enhanced scopes for comprehensive access
        $Scopes = @(
            "User.Read",
            "User.ReadWrite.All",
            "Directory.Read.All",
            "Group.Read.All",
            "Organization.Read.All",
            "Policy.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "Reports.Read.All",
            "SecurityEvents.Read.All"
        )
        
        # Step 1: Connect to Microsoft Graph with enhanced authentication
        try {
            Write-Host "Authenticating with Microsoft Graph..." -ForegroundColor Cyan
            
            # Try interactive browser authentication first
            try {
                Write-Host "Attempting interactive browser authentication..." -ForegroundColor Yellow
                Connect-MgGraph -Scopes $Scopes -Audience 'organizations' -NoWelcome -ErrorAction Stop
            }
            catch {
                Write-Warning "Interactive browser authentication failed: $($_.Exception.Message)"
                Write-Host "Trying device code authentication..." -ForegroundColor Yellow
                try {
                    Connect-MgGraph -Scopes $Scopes -Audience 'organizations' -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
                }
                catch {
                    Write-Warning "Device code authentication failed: $($_.Exception.Message)"
                    Write-Host "Trying basic interactive authentication..." -ForegroundColor Yellow
                    Connect-MgGraph -Scopes $Scopes -Audience 'organizations' -ErrorAction Stop
                }
            }
            
            # Verify Graph connection
            $GraphContext = Get-MgContext
            if ($GraphContext) {
                $Global:IsConnected = $true
                $ConnectionResults.Graph = $true
                Write-Host "Microsoft Graph connected successfully" -ForegroundColor Green
                
                # Get account information from context
                $AccountId = $GraphContext.Account
                $TenantId = $GraphContext.TenantId
                
                Write-Host ("  Account: {0}" -f $AccountId) -ForegroundColor Gray
                Write-Host ("  Tenant: {0}" -f $TenantId) -ForegroundColor Gray

                Initialize-Module -Modules @("Microsoft.Graph.Users","Microsoft.Graph.Identity.DirectoryManagement")
                
                # Get current user
                try {
                    $Global:CurrentUser = Get-MgUser -UserId "me" -ErrorAction Stop
                    Write-Host "Current user retrieved successfully" -ForegroundColor Green
                }
                catch {
                    if ($AccountId) {
                        try {
                            $Global:CurrentUser = Get-MgUser -UserId $AccountId -ErrorAction Stop
                            Write-Host "Current user retrieved using account ID" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Could not retrieve current user details: $($_.Exception.Message)"
                            $Global:CurrentUser = $null
                        }
                    }
                }
                
                # Get organization information
                try {
                    $OrgRaw = Get-MgOrganization -Property "DisplayName,Id,VerifiedDomains" -ErrorAction Stop
                    $OrgInfo = @($OrgRaw)[0]
                    if ($OrgInfo) {
                        $Global:TenantInfo = $OrgInfo
                        $CompanyDisplayName = if ($OrgInfo.DisplayName) { $OrgInfo.DisplayName } else { "Microsoft 365 Tenant" }
                        Write-Host "Organization info retrieved: $CompanyDisplayName" -ForegroundColor Green

                        # Determine and hint default domain for new user email auto-fill
                        try {
                            $Global:DefaultDomain = Get-DefaultDomainName
                            Set-DefaultDomainHint
                        } catch {}
                    }
                }
                catch {
                    Write-Warning "Could not retrieve organization info: $($_.Exception.Message)"
                    $CompanyDisplayName = "Microsoft 365 Tenant"
                }
            }
            else {
                throw "Failed to establish Graph context"
            }
        }
        catch {
            Write-Warning "Microsoft Graph connection failed: $($_.Exception.Message)"
            $ConnectionResults.Graph = $false
            Show-ErrorMessage "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            return
        }
        
        # Step 2: Enhanced Exchange Online Connection with Multiple Methods
        $Global:IsExchangeConnected = Connect-ExchangeOnlineEnhanced -AccountId $AccountId -TenantId $TenantId
        $ConnectionResults.Exchange = $Global:IsExchangeConnected
        
        # Update UI based on connection results
        if ($ConnectionResults.Graph) {
            # Update UI with company information
            $Window.FindName("AuthStatus").Text = "Connected"
            $Window.FindName("CompanyName").Text = $CompanyDisplayName
            
            # Update button visibility - hide connect, show disconnect
            $Window.FindName("ConnectButton").Visibility = "Collapsed"
            $Window.FindName("DisconnectButton").Visibility = "Visible"
            $Window.FindName("DisconnectButton").IsEnabled = $true
            
            # Load initial admin data
            Get-AdminOverview
            # Run diagnostics to surface missing permissions/modules
            Show-PermissionsDiagnostic
            
            Write-Host "MSAL.NET Single Sign-On authentication completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Failed to connect to Microsoft Graph. Please check your credentials and try again." -ForegroundColor Red
        }
    }
    catch {
        Show-ErrorMessage "MSAL.NET authentication failed: $($_.Exception.Message)"
        Write-Error "MSAL.NET authentication failed: $($_.Exception.Message)"
    }
}

# Function to get enhanced shared mailbox count using Exchange Online
function Get-EnhancedSharedMailboxCount {
    try {
        Write-Host "Enhanced shared mailbox detection..." -ForegroundColor Cyan
        
        if ($Global:IsExchangeConnected) {
            try {
                Write-Host "Retrieving shared mailboxes from Exchange Online..." -ForegroundColor Yellow
                try {
                    $SharedMailboxes = Get-EXOMailbox -Filter "RecipientTypeDetails -eq 'SharedMailbox'" -ResultSize Unlimited -ErrorAction Stop
                } catch {
                    $SharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
                }
                
                Write-Host "Found $($SharedMailboxes.Count) shared mailboxes in Exchange Online" -ForegroundColor Green
                
                if ($SharedMailboxes.Count -gt 0) {
                    Write-Host "Shared mailboxes found:" -ForegroundColor Cyan
                    $SharedMailboxes | Select-Object -First 10 | ForEach-Object {
                        Write-Host "  - $($_.DisplayName) [$($_.PrimarySmtpAddress)]" -ForegroundColor Gray
                    }
                    if ($SharedMailboxes.Count -gt 10) {
                        Write-Host "  ... and $($SharedMailboxes.Count - 10) more" -ForegroundColor Gray
                    }
                }
                
                return $SharedMailboxes.Count
            }
            catch {
                Write-Warning "Exchange Online query failed: $($_.Exception.Message)"
                Write-Host "Falling back to Graph API detection..." -ForegroundColor Yellow
                return Get-SharedMailboxCountFallback
            }
        } else {
            Write-Host "Exchange Online not connected, using Graph API fallback..." -ForegroundColor Yellow
            return Get-SharedMailboxCountFallback
        }
    }
    catch {
        Write-Warning "Enhanced shared mailbox detection failed: $($_.Exception.Message)"
        return Get-SharedMailboxCountFallback
    }
}

# Fallback function for shared mailbox detection
function Get-SharedMailboxCountFallback {
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users")
        Write-Host "Using Graph API fallback method for shared mailbox detection..." -ForegroundColor Yellow
        
        $AllUsers = Get-MgUser -All -Property @(
            "Id", "DisplayName", "UserPrincipalName", "Mail", "AccountEnabled", 
            "AssignedLicenses", "UserType"
        )
        
        # Traditional shared mailbox detection
        $TraditionalSharedMailboxes = $AllUsers | Where-Object { 
            $_.AccountEnabled -eq $false -and 
            $_.AssignedLicenses.Count -eq 0
        }
        
        # Pattern-based detection
        $PatternBasedSharedMailboxes = $AllUsers | Where-Object {
            $_.DisplayName -and (
                $_.DisplayName -like "*shared*" -or 
                $_.DisplayName -like "*info*" -or
                $_.DisplayName -like "*support*" -or
                $_.DisplayName -like "*admin*" -or
                $_.DisplayName -like "*reception*" -or
                $_.DisplayName -like "*sales*" -or
                $_.DisplayName -like "*hr*" -or
                $_.DisplayName -like "*finance*" -or
                $_.DisplayName -like "*noreply*" -or
                $_.DisplayName -like "*no-reply*" -or
                $_.DisplayName -like "*donotreply*" -or
                $_.DisplayName -like "*service*" -or
                $_.DisplayName -like "*team*" -or
                $_.DisplayName -like "*group*" -or
                $_.DisplayName -like "*mailbox*" -or
                $_.DisplayName -like "*contact*" -or
                $_.DisplayName -like "*booking*" -or
                $_.DisplayName -like "*calendar*"
            )
        }
        
        # Combine and remove duplicates
        $AllPotentialSharedMailboxes = @()
        $AllPotentialSharedMailboxes += $TraditionalSharedMailboxes
        $AllPotentialSharedMailboxes += $PatternBasedSharedMailboxes
        
        $UniqueSharedMailboxes = $AllPotentialSharedMailboxes | Sort-Object Id -Unique
        
        # Filter out obvious user accounts
        $FilteredSharedMailboxes = $UniqueSharedMailboxes | Where-Object {
            -not ($_.DisplayName -match "^[A-Za-z]+ [A-Za-z]+$" -and $_.AccountEnabled -eq $true) -and
            -not ($_.UserPrincipalName -match "^[a-zA-Z]+\.[a-zA-Z]+\d*@" -and $_.AccountEnabled -eq $true)
        }
        
        Write-Host "Fallback shared mailbox detection results:" -ForegroundColor Yellow
        Write-Host "  - Traditional (disabled, no licenses): $($TraditionalSharedMailboxes.Count)" -ForegroundColor Gray
        Write-Host "  - Pattern-based (naming): $($PatternBasedSharedMailboxes.Count)" -ForegroundColor Gray
        Write-Host "  - Total unique potential: $($UniqueSharedMailboxes.Count)" -ForegroundColor Gray
        Write-Host "  - After filtering: $($FilteredSharedMailboxes.Count)" -ForegroundColor Yellow
        Write-Host "Note: For accurate results, connect to Exchange Online" -ForegroundColor Yellow
        
        return $FilteredSharedMailboxes.Count
    }
    catch {
        Write-Warning "Error in fallback shared mailbox detection: $($_.Exception.Message)"
        return 0
    }
}

# Function to disconnect from services
function Disconnect-FromGraph {
    try {
        Write-Host "Disconnecting from Microsoft 365 services..." -ForegroundColor Yellow
        
        $DisconnectionResults = @()
        
        # Disconnect from Microsoft Graph
        try {
            Disconnect-MgGraph
            $Global:IsConnected = $false
            $DisconnectionResults += "Microsoft Graph disconnected"
            Write-Host "Microsoft Graph disconnected" -ForegroundColor Green
        }
        catch {
            $DisconnectionResults += "Microsoft Graph disconnect failed: $($_.Exception.Message)"
            Write-Warning "Microsoft Graph disconnect failed: $($_.Exception.Message)"
        }
        
        # Disconnect from Exchange Online
        if ($Global:IsExchangeConnected) {
            try {
                Disconnect-ExchangeOnline -Confirm:$false
                $Global:IsExchangeConnected = $false
                $DisconnectionResults += "Exchange Online disconnected"
                Write-Host "Exchange Online disconnected" -ForegroundColor Green
            }
            catch {
                $DisconnectionResults += "Exchange Online disconnect failed: $($_.Exception.Message)"
                Write-Warning "Exchange Online disconnect failed: $($_.Exception.Message)"
            }
        }
        
        # Clear global variables
        $Global:CurrentUser = $null
        $Global:TenantInfo = $null
        $Global:MsalToken = $null
        
        # Update UI
        $Window.FindName("AuthStatus").Text = "Not Connected"
        $Window.FindName("CompanyName").Text = ""
        
        # Reset stats
        $Window.FindName("UserCount").Text = "--"
        $Window.FindName("GroupCount").Text = "--"
        $Window.FindName("DeviceCount").Text = "--"
        $Window.FindName("LicenseCount").Text = "--"
        
        # Reset Entra ID stats
        $Window.FindName("ActiveUserCount").Text = "--"
        $Window.FindName("MfaEnabledCount").Text = "--"
        $Window.FindName("SharedMailboxCount").Text = "--"
        
        # Reset Intune stats
        $Window.FindName("ManagedDeviceCount").Text = "--"
        $Window.FindName("NonCompliantDeviceCount").Text = "--"
        $Window.FindName("PolicyCount").Text = "--"
        $Window.FindName("AppCount").Text = "--"
        
        # Reset Security stats
        $Window.FindName("SecurityAlertCount").Text = "--"
        $Window.FindName("ComplianceScore").Text = "--"
        $Window.FindName("ConditionalAccessPolicyCount").Text = "--"
        
        # Update button visibility - show connect, hide disconnect
        $Window.FindName("ConnectButton").Visibility = "Visible"
        $Window.FindName("DisconnectButton").Visibility = "Collapsed"
        $Window.FindName("ConnectButton").IsEnabled = $true
        
        Write-Host "Disconnection completed!" -ForegroundColor Yellow
    }
    catch {
        Show-ErrorMessage "Error during disconnection: $($_.Exception.Message)"
    }
}

# Function to get admin overview data
function Get-AdminOverview {
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users","Microsoft.Graph.Groups","Microsoft.Graph.DeviceManagement","Microsoft.Graph.Identity.DirectoryManagement")
        Write-Host "Loading admin overview..." -ForegroundColor Yellow
        
        # Get user count
        try {
            $UserCount = $null
            try {
                $null = Get-MgUser -Top 1 -ConsistencyLevel eventual -CountVariable UserCount -ErrorAction Stop
            } catch {}
            if (-not $UserCount -or $UserCount -lt 1) {
                $users = Get-MgUser -All -Property "Id" -ErrorAction Stop
                $UserCount = @($users).Count
            }
            if (-not $UserCount) { $UserCount = 0 }
            $Window.FindName("UserCount").Text = $UserCount.ToString()
        }
        catch {
            $Window.FindName("UserCount").Text = "N/A"
            Write-Warning "Could not get user count: $($_.Exception.Message)"
        }
        
        # Get group count
        try {
            $GroupCount = $null
            try {
                $null = Get-MgGroup -Top 1 -ConsistencyLevel eventual -CountVariable GroupCount -ErrorAction Stop
            } catch {}
            if (-not $GroupCount -or $GroupCount -lt 1) {
                $groups = Get-MgGroup -All -Property "Id" -ErrorAction Stop
                $GroupCount = @($groups).Count
            }
            if (-not $GroupCount) { $GroupCount = 0 }
            $Window.FindName("GroupCount").Text = $GroupCount.ToString()
        }
        catch {
            $Window.FindName("GroupCount").Text = "N/A"
            Write-Warning "Could not get group count: $($_.Exception.Message)"
        }
        
        # Get device count
        try {
            $DeviceCount = $null
            try {
                $null = Get-MgDeviceManagementManagedDevice -ConsistencyLevel eventual -CountVariable DeviceCount -Top 1 -ErrorAction Stop
            } catch {}
            if (-not $DeviceCount -or $DeviceCount -lt 1) {
                $devices = Get-MgDeviceManagementManagedDevice -All -Property "Id" -ErrorAction Stop
                $DeviceCount = @($devices).Count
            }
            if (-not $DeviceCount) { $DeviceCount = 0 }
            $Window.FindName("DeviceCount").Text = $DeviceCount.ToString()
        }
        catch {
            $Window.FindName("DeviceCount").Text = "N/A"
            Write-Warning "Could not get device count (may require Intune license/permissions): $($_.Exception.Message)"
        }
        
        # Get license count
        try {
            $Licenses = Get-MgSubscribedSku
            $Window.FindName("LicenseCount").Text = $Licenses.Count.ToString()
        }
        catch {
            $Window.FindName("LicenseCount").Text = "N/A"
            Write-Warning "Could not get license count: $($_.Exception.Message)"
        }
        
        Write-Host "Admin overview loaded successfully!" -ForegroundColor Green
    }
    catch {
        Show-ErrorMessage "Failed to load admin overview: $($_.Exception.Message)"
        Write-Error "Admin overview failed: $($_.Exception.Message)"
    }
}

# Function to get Entra ID dashboard data
function Get-EntraIdStatistic {
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users","Microsoft.Graph.Users.Actions","Microsoft.Graph.Reports")
        Write-Host "Loading Entra ID statistics..." -ForegroundColor Yellow
        
        # Get active user count
        try {
            $null = Get-MgUser -Filter "accountEnabled eq true" -Top 1 -ConsistencyLevel eventual -CountVariable ActiveUserCount
            $Window.FindName("ActiveUserCount").Text = $ActiveUserCount.ToString()
        }
        catch {
            $Window.FindName("ActiveUserCount").Text = "Error"
            Write-Warning "Could not get active user count: $($_.Exception.Message)"
        }
        
        # Get MFA enabled count via Reports API (delegated: Reports.Read.All)
        try {
            $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
            $MfaEnabledCount = ($reg | Where-Object { $_.IsMfaRegistered -eq $true }).Count
            $Window.FindName("MfaEnabledCount").Text = $MfaEnabledCount.ToString()
        }
        catch {
            $Window.FindName("MfaEnabledCount").Text = "N/A"
            Write-Warning "Could not get MFA enabled count (requires Reports.Read.All): $($_.Exception.Message)"
        }
        
        # Get shared mailbox count
        try {
            Write-Host "Detecting shared mailboxes..." -ForegroundColor Cyan
            
            if ($Global:IsExchangeConnected) {
                $SharedMailboxCount = Get-EnhancedSharedMailboxCount
            } else {
                $SharedMailboxCount = Get-SharedMailboxCountFallback
            }
            
            $Window.FindName("SharedMailboxCount").Text = $SharedMailboxCount.ToString()
        }
        catch {
            $Window.FindName("SharedMailboxCount").Text = "N/A"
            Write-Warning "Could not get shared mailbox count: $($_.Exception.Message)"
        }
        
        Write-Host "Entra ID statistics loaded successfully!" -ForegroundColor Green
    }
    catch {
        Show-ErrorMessage "Failed to load Entra ID statistics: $($_.Exception.Message)"
        Write-Error "Entra ID stats failed: $($_.Exception.Message)"
    }
}

# Function to get Intune dashboard data
function Get-IntuneStatistic {
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    
    try {
        Initialize-Module -Modules @("Microsoft.Graph.DeviceManagement")
        Write-Host "Loading Intune statistics..." -ForegroundColor Yellow
        
        # Get managed device count
        try {
            # Method 1: Use count header with eventual consistency
            $ManagedDeviceCount = $null
            try {
                $null = Get-MgDeviceManagementManagedDevice -ConsistencyLevel eventual -CountVariable ManagedDeviceCount -Top 1 -ErrorAction Stop
            } catch {}
            # Method 2: Enumerate and count if header didn't populate
            if (-not $ManagedDeviceCount -or $ManagedDeviceCount -lt 1) {
                $devices = Get-MgDeviceManagementManagedDevice -All -Property "Id" -ErrorAction Stop
                $ManagedDeviceCount = @($devices).Count
            }
            # Method 3: Beta fallback for tenants/features only exposed in beta
            if (-not $ManagedDeviceCount -or $ManagedDeviceCount -lt 1) {
                if (Get-Command -Name Get-MgBetaDeviceManagementManagedDevice -ErrorAction SilentlyContinue) {
                    $devicesBeta = Get-MgBetaDeviceManagementManagedDevice -All -Property "Id" -ErrorAction Stop
                    $ManagedDeviceCount = @($devicesBeta).Count
                }
            }
            $Window.FindName("ManagedDeviceCount").Text = $ManagedDeviceCount.ToString()
        }
        catch {
            $Window.FindName("ManagedDeviceCount").Text = "N/A"
            Write-Warning "Could not get managed device count: $($_.Exception.Message)"
        }
        
        # Get non-compliant device count
        try {
            $AllDevices = Get-MgDeviceManagementManagedDevice -All -Property "Id,ComplianceState"
            $NonCompliantCount = ($AllDevices | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count
            $Window.FindName("NonCompliantDeviceCount").Text = $NonCompliantCount.ToString()
        }
        catch {
            $Window.FindName("NonCompliantDeviceCount").Text = "N/A"
            Write-Warning "Could not get non-compliant device count: $($_.Exception.Message)"
        }
        
        # Get policy count
        try {
            try {
                $null = Get-MgDeviceManagementDeviceCompliancePolicy -Top 1 -ConsistencyLevel eventual -CountVariable policyCount
                $Window.FindName("PolicyCount").Text = $policyCount.ToString()
            }
            catch {
                $Policies = Get-MgDeviceManagementDeviceCompliancePolicy -All
                $Window.FindName("PolicyCount").Text = ($Policies.Count).ToString()
            }
        }
        catch {
            $Window.FindName("PolicyCount").Text = "N/A"
            Write-Warning "Could not get policy count: $($_.Exception.Message)"
        }
        
        # Get app count
        try {
            try {
                $AppsAll = Get-MgDeviceAppManagementMobileApp -All
                $Window.FindName("AppCount").Text = ($AppsAll.Count).ToString()
            }
            catch {
                $Window.FindName("AppCount").Text = "N/A"
                Write-Warning "Could not get app count (install Microsoft.Graph.DeviceAppManagement or grant DeviceManagementApps.Read.All): $($_.Exception.Message)"
            }
        }
        catch {
            $Window.FindName("AppCount").Text = "N/A"
            Write-Warning "Could not get app count: $($_.Exception.Message)"
        }
        
        Write-Host "Intune statistics loaded successfully!" -ForegroundColor Green
    }
    catch {
        Show-ErrorMessage "Failed to load Intune statistics: $($_.Exception.Message)"
        Write-Error "Intune stats failed: $($_.Exception.Message)"
    }
}

# Helper: robust Conditional Access policies count (v1, beta, and raw REST)
function Get-ConditionalAccessPolicyCount {
    Initialize-Module -Modules @("Microsoft.Graph.Identity.SignIns")
    $count = 0
    $source = "v1.0"

    # v1.0 cmdlet
    try {
        $v1 = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $count = @($v1).Count
        $source = "v1.0"
    } catch {}

    # beta cmdlet
    try {
        if (Get-Command -Name Get-MgBetaIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue) {
            $beta = Get-MgBetaIdentityConditionalAccessPolicy -All -ErrorAction Stop
            if (@($beta).Count -gt $count) {
                $count = @($beta).Count
                $source = "beta"
            }
        }
    } catch {}

    # v1.0 raw REST
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999"
        if ($resp.value) {
            $restV1Count = @($resp.value).Count
            if ($restV1Count -gt $count) {
                $count = $restV1Count
                $source = "v1.0 REST"
            }
        }
    } catch {}

    # beta raw REST
    try {
        $respB = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?$top=999"
        if ($respB.value) {
            $restBetaCount = @($respB.value).Count
            if ($restBetaCount -gt $count) {
                $count = $restBetaCount
                $source = "beta REST"
            }
        }
    } catch {}

    return @{ Count = $count; Source = $source }
}

# Function to get Security dashboard data
function Get-SecurityStatistic {
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    
    try {
        Write-Host "Loading Security statistics..." -ForegroundColor Yellow
        
        # Get security alerts count
        try {
            Initialize-Module -Modules @("Microsoft.Graph.Security")
            $alertCount = 0
            $usedMethod = "cmdlet"

            if (Get-Command -Name Get-MgSecurityAlertV2 -ErrorAction SilentlyContinue) {
                try {
                    $null = Get-MgSecurityAlertV2 -Top 1 -ConsistencyLevel eventual -CountVariable alertCount -ErrorAction Stop
                } catch {
                    try {
                        $alerts = Get-MgSecurityAlertV2 -All -ErrorAction Stop
                        $alertCount = @($alerts).Count
                    } catch {}
                }
            } elseif (Get-Command -Name Get-MgSecurityAlert -ErrorAction SilentlyContinue) {
                try {
                    $null = Get-MgSecurityAlert -Top 1 -ConsistencyLevel eventual -CountVariable alertCount -ErrorAction Stop
                } catch {
                    try {
                        $alerts = Get-MgSecurityAlert -All -ErrorAction Stop
                        $alertCount = @($alerts).Count
                    } catch {}
                }
            } else {
                $usedMethod = "rest"
            }

            if ($usedMethod -eq "rest" -or -not $alertCount) {
                try {
                    $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/alerts?$count=true&$top=1" -Headers @{ "ConsistencyLevel" = "eventual" }
                    if ($resp.'@odata.count') { $alertCount = [int]$resp.'@odata.count' }
                } catch {
                    try {
                        $respB = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/alerts_v2?$count=true&$top=1" -Headers @{ "ConsistencyLevel" = "eventual" }
                        if ($respB.'@odata.count') { $alertCount = [int]$respB.'@odata.count' }
                    } catch {}
                }
            }

            if ($alertCount -ge 0) {
                $Window.FindName("SecurityAlertCount").Text = $alertCount.ToString()
            } else {
                $Window.FindName("SecurityAlertCount").Text = "N/A"
            }
        }
        catch {
            $Window.FindName("SecurityAlertCount").Text = "N/A"
            Write-Warning "Could not get security alert count: $($_.Exception.Message)"
        }
        
        # Get compliance/security score
        try {
            Initialize-Module -Modules @("Microsoft.Graph.Security")
            $score = $null
            try {
                $ss = Get-MgSecuritySecureScore -Top 1 -OrderBy "createdDateTime desc" -ErrorAction Stop
                if ($ss) { $score = [double]$ss[0].CurrentScore }
            } catch {}

            if (-not $score) {
                try {
                    $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores?$top=1&$orderby=createdDateTime desc"
                    if ($resp.value -and $resp.value.Count -gt 0) {
                        $score = [double]$resp.value[0].currentScore
                    }
                } catch {
                    try {
                        $respB = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/secureScores?$top=1&$orderby=createdDateTime desc"
                        if ($respB.value -and $respB.value.Count -gt 0) {
                            $score = [double]$respB.value[0].currentScore
                        }
                    } catch {}
                }
            }

            if ($null -ne $score) {
                $Window.FindName("ComplianceScore").Text = ([math]::Round($score,0)).ToString()
            } else {
                $Window.FindName("ComplianceScore").Text = "N/A"
            }
        }
        catch {
            $Window.FindName("ComplianceScore").Text = "N/A"
            Write-Warning "Secure Score not accessible (requires Security.Read.All). Error: $($_.Exception.Message)"
        }
        
        # Get conditional access policy count
        try {
            Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan
            $ca = Get-ConditionalAccessPolicyCount
            $caCount = $ca.Count
            $Window.FindName("ConditionalAccessPolicyCount").Text = $caCount.ToString()
            Write-Host ("Found {0} Conditional Access policies ({1})" -f $caCount, $ca.Source) -ForegroundColor Green
        }
        catch {
            $Window.FindName("ConditionalAccessPolicyCount").Text = "Error"
            if ($_.Exception.Message -like "*Insufficient privileges*" -or $_.Exception.Message -like "*Forbidden*") {
                Write-Warning "Insufficient permissions to read Conditional Access policies. Required: Policy.Read.All"
            }
            elseif ($_.Exception.Message -like "*not found*" -or $_.Exception.Message -like "*does not exist*") {
                Write-Warning "Conditional Access policies endpoint not available. May require Azure AD Premium license."
            }
            else {
                Write-Warning "Could not get conditional access policy count: $($_.Exception.Message)"
            }
        }
        
        Write-Host "Security statistics loaded successfully!" -ForegroundColor Green
    }
    catch {
        Show-ErrorMessage "Failed to load Security statistics: $($_.Exception.Message)"
        Write-Error "Security stats failed: $($_.Exception.Message)"
    }
}

# Entra helpers: load users into ComboBoxes and show profile
function Get-EntraUser {
    param(
        [string]$ComboName,
        [int]$Top = 500
    )
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users")
        Write-Host ("Loading users into '{0}'..." -f $ComboName) -ForegroundColor Yellow

        $users = @()
        try {
            # Prefer a fast, bounded list (sorted) for UI responsiveness
            $users = Get-MgUser -Top $Top -OrderBy "displayName" -Property "Id,DisplayName,UserPrincipalName,JobTitle,AccountEnabled" -ErrorAction Stop
        } catch {
            # Fallback to enumerate if -Top fails in some environments
            $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,JobTitle,AccountEnabled"
        }

        $items = foreach ($u in $users) {
            $disp = if ($u.DisplayName) { $u.DisplayName } else { $u.UserPrincipalName }
            [PSCustomObject]@{
                DisplayName        = $u.DisplayName
                UserPrincipalName  = $u.UserPrincipalName
                JobTitle           = $u.JobTitle
                DisplayText        = ("{0} <{1}>" -f $disp, $u.UserPrincipalName)
            }
        }

        $combo = $Window.FindName($ComboName)
        if ($combo) {
            $combo.DisplayMemberPath = "DisplayText"
            $combo.SelectedValuePath = "UserPrincipalName"
            $combo.ItemsSource = $items
            if ($items.Count -gt 0 -and $combo.SelectedIndex -lt 0) { $combo.SelectedIndex = 0 }
            Write-Host ("Loaded {0} users into {1}" -f $items.Count, $ComboName) -ForegroundColor Green
        } else {
            Write-Warning ("ComboBox '{0}' not found in XAML" -f $ComboName)
        }
    }
    catch {
        Write-Warning ("Failed to load users: {0}" -f $_.Exception.Message)
    }
}

function Show-SelectedUserProfile {
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users","Microsoft.Graph.Groups")
        $combo = $Window.FindName("UserSearchComboBox")
        if (-not $combo) {
            Show-ErrorMessage "User selector not found"
            return
        }

        # Resolve UPN from selection or typed text
        $upn = $null
        $typed = $null
        try { $typed = ($combo.Text).Trim() } catch {}

        # Prefer SelectedValue if SelectedValuePath is set
        if ($combo.SelectedValue) {
            $upn = [string]$combo.SelectedValue
        }

        # Fall back to SelectedItem.UserPrincipalName
        if (-not $upn -and $combo.SelectedItem -and $combo.SelectedItem.PSObject -and $combo.SelectedItem.PSObject.Properties['UserPrincipalName']) {
            $upn = $combo.SelectedItem.UserPrincipalName
        }

        # Parse typed text (supports "Name <upn>" or direct UPN)
        if (-not $upn -and $typed) {
            if ($typed -match '<([^>]+)>\s*$') {
                $upn = $Matches[1]
            } elseif ($typed -match '@') {
                $upn = $typed
            }
        }

        # Last resort: try to guess by displayName prefix
        $u = $null
        if (-not $upn -and $typed) {
            try {
                $filterText = $typed.Replace("'", "''")
                $guess = Get-MgUser -Filter "startsWith(displayName,'$filterText')" -Top 1 -ErrorAction Stop
                if ($guess) {
                    $upn = $guess.UserPrincipalName
                    $u = $guess
                }
            } catch {}
        }

        if (-not $upn) {
            Show-ErrorMessage "Enter or select a user (UPN or Name <upn>) and try again"
            return
        }

        Write-Host ("Loading user profile for {0}..." -f $upn) -ForegroundColor Yellow

        # Fetch user; fall back to basic fetch if -Property is not supported
        $u = $null
        try {
            $u = Get-MgUser -UserId $upn -Property "id,displayName,userPrincipalName,mail,jobTitle,department,officeLocation,companyName,mobilePhone,accountEnabled,createdDateTime" -ErrorAction Stop
        } catch {
            Write-Warning ("Get-MgUser with -Property failed, retrying basic fetch: {0}" -f $_.Exception.Message)
            $u = Get-MgUser -UserId $upn -ErrorAction Stop
        }

        # Groups (transitive) with cmdlet, then REST fallback, then direct memberOf
        $groupNames = @()
        try {
            $m = Get-MgUserTransitiveMemberOf -UserId $u.Id -All -ErrorAction Stop
            foreach ($obj in $m) {
                $dn = $null
                if ($obj.PSObject.Properties['DisplayName']) {
                    $dn = $obj.DisplayName
                } elseif ($obj.AdditionalProperties -and $obj.AdditionalProperties.ContainsKey('displayName')) {
                    $dn = $obj.AdditionalProperties['displayName']
                }
                if ($dn) { $groupNames += $dn }
            }
        } catch {
            Write-Warning ("TransitiveMemberOf cmdlet failed: {0}" -f $_.Exception.Message)
        }

        if (-not $groupNames -or $groupNames.Count -eq 0) {
            try {
                # REST fallback for transitive groups
                $next = "https://graph.microsoft.com/v1.0/users/$($u.Id)/transitiveMemberOf`?$select=displayName&`$top=999"
                while ($next) {
                    $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
                    if ($resp.value) {
                        foreach ($g in $resp.value) {
                            $dn = $g.displayName
                            if ($dn) { $groupNames += $dn }
                        }
                    }
                    $next = $resp.'@odata.nextLink'
                }
            } catch {
                Write-Warning ("REST transitiveMemberOf fallback failed: {0}" -f $_.Exception.Message)
            }
        }

        if (-not $groupNames -or $groupNames.Count -eq 0) {
            try {
                # Fallback to direct memberOf if transitive did not return names
                $m2 = Get-MgUserMemberOf -UserId $u.Id -All -ErrorAction Stop
                foreach ($obj in $m2) {
                    $dn = $null
                    if ($obj.PSObject.Properties['DisplayName']) {
                        $dn = $obj.DisplayName
                    } elseif ($obj.AdditionalProperties -and $obj.AdditionalProperties.ContainsKey('displayName')) {
                        $dn = $obj.AdditionalProperties['displayName']
                    }
                    if ($dn) { $groupNames += $dn }
                }
            } catch {
                Write-Warning ("Direct memberOf fallback failed: {0}" -f $_.Exception.Message)
            }
        }
        if ($groupNames) { $groupNames = $groupNames | Sort-Object -Unique } else { $groupNames = @() }

        # Shared mailboxes (requires EXO connection)
        $userShared = @()
        if ($Global:IsExchangeConnected) {
            try {
                $shared = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
                foreach ($mb in $shared) {
                    $hasAccess = $false
                    try {
                        $p = Get-EXOMailboxPermission -Identity $mb.PrimarySmtpAddress -User $upn -ErrorAction SilentlyContinue | Where-Object { $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited }
                        if ($p) { $hasAccess = $true }
                    } catch {}
                    if (-not $hasAccess) {
                        try {
                            $sa = Get-EXORecipientPermission -Identity $mb.PrimarySmtpAddress -Trustee $upn -AccessRights SendAs -ErrorAction SilentlyContinue
                            if ($sa) { $hasAccess = $true }
                        } catch {}
                    }
                    if ($hasAccess) {
                        $userShared += ("{0} <{1}>" -f $mb.DisplayName, $mb.PrimarySmtpAddress)
                    }
                }
            } catch {
                Write-Warning ("Failed to enumerate shared mailboxes: {0}" -f $_.Exception.Message)
            }
        }

        # Build display lines with emoji labels
        $enabledText = if ($u.AccountEnabled) { "✅ Enabled: True" } else { "⛔ Disabled: False" }
        $lines = @(
            "👤 Display Name: {0}" -f ($u.DisplayName)
            "📨 UPN: {0}" -f ($u.UserPrincipalName)
            "📧 Email: {0}" -f ($u.Mail)
            "💼 Job Title: {0}" -f ($u.JobTitle)
            "🏢 Department: {0}" -f ($u.Department)
            "📍 Office: {0}" -f ($u.OfficeLocation)
            "🏭 Company: {0}" -f ($u.CompanyName)
            "📱 Mobile: {0}" -f ($u.MobilePhone)
            "{0}" -f $enabledText
            "🗓️ Created: {0}" -f ($u.CreatedDateTime)
        )

        $lines += ("👥 Groups ({0}): {1}" -f $groupNames.Count, (($groupNames | Select-Object -First 15) -join ", "))
        if ($groupNames.Count -gt 15) { $lines += ("... and {0} more groups" -f ($groupNames.Count - 15)) }

        if ($Global:IsExchangeConnected) {
            $lines += ("📮 Shared Mailboxes ({0})" -f $userShared.Count)
            if ($userShared.Count -gt 0) {
                $lines += ($userShared | Select-Object -First 10)
                if ($userShared.Count -gt 10) { $lines += ("... and {0} more" -f ($userShared.Count - 10)) }
            }
        } else {
            $lines += "📮 Shared Mailboxes: Connect to Exchange Online to enumerate mailbox permissions"
        }

        $Window.FindName("UserProfileText").Text = ($lines -join "`r`n")
        $Window.FindName("UserProfileBorder").Visibility = "Visible"
        Write-Host "User profile loaded" -ForegroundColor Green
    }
    catch {
        Show-ErrorMessage ("Failed to load user profile: {0}" -f $_.Exception.Message)
    }
}

# User creation and domain helpers
function Get-DefaultDomainName {
    try {
        $tenant = $null
        if ($Global:TenantInfo) { $tenant = @($Global:TenantInfo)[0] }
        if (-not $tenant) {
            $tenant = @((Get-MgOrganization -Property "VerifiedDomains" -ErrorAction SilentlyContinue))[0]
        }
        if ($tenant -and $tenant.VerifiedDomains) {
            $domains = @($tenant.VerifiedDomains)
            $def = $domains | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
            if (-not $def) { $def = $domains | Where-Object { $_.IsInitial -eq $true } | Select-Object -First 1 }
            if (-not $def) { $def = $domains | Select-Object -First 1 }
            if ($def) {
                if ($def.PSObject.Properties['Name'] -and $def.Name) { return $def.Name }
                if ($def.PSObject.Properties['Id'] -and $def.Id) { return $def.Id }
                if ($def.PSObject.Properties['AdditionalProperties'] -and $def.AdditionalProperties.ContainsKey('name')) { return $def.AdditionalProperties['name'] }
            }
        }
    } catch {}
    return $null
}

function Set-DefaultDomainHint {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    if (-not $PSCmdlet.ShouldProcess("Strata365 UI","Set default domain hint")) { return }
    try {
        if (-not $Global:DefaultDomain -or -not $Global:DefaultDomain.Length) {
            $Global:DefaultDomain = Get-DefaultDomainName
        }
        $emailBox = $Window.FindName("NewUserEmailTextBox")
        if ($emailBox) {
            if ($Global:DefaultDomain) {
                $hint = ("local-part@{0}" -f $Global:DefaultDomain)
                # WPF TextBox has no placeholder; use ToolTip and Tag as hint
                $emailBox.ToolTip = $hint
                $emailBox.Tag = $hint
            }
            Register-EmailAutoDomain
        }
    } catch {}
}

function Register-EmailAutoDomain {
    try {
        $emailBox = $Window.FindName("NewUserEmailTextBox")
        if (-not $emailBox) { return }
        if (-not $Global:_EmailLostFocusHooked) {
            $emailBox.Add_LostFocus({
                try {
                    $box = $Window.FindName("NewUserEmailTextBox")
                    if ($box) {
                        $txt = ($box.Text).Trim()
                        if ($txt.Length -gt 0 -and ($txt -notmatch '@')) {
                            if (-not $Global:DefaultDomain) { $Global:DefaultDomain = Get-DefaultDomainName }
                            if ($Global:DefaultDomain) {
                                $box.Text = ("{0}@{1}" -f $txt, $Global:DefaultDomain)
                            }
                        }
                    }
                } catch {}
                Update-CreateUserButtonState
            })
            $Global:_EmailLostFocusHooked = $true
        }
    } catch {}
}

function Update-CreateUserButtonState {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    if (-not $PSCmdlet.ShouldProcess("Strata365 UI","Update create-user button state")) { return }
    try {
        $btn  = $Window.FindName("CreateUserButton")
        $name = $Window.FindName("NewUserNameTextBox")
        $mail = $Window.FindName("NewUserEmailTextBox")
        if (-not $btn -or -not $name -or -not $mail) { return }
        $hasName = ($name.Text -replace '\s','').Length -gt 0
        $hasEmailOrDomain = ($mail.Text.Trim().Length -gt 0) -or ($Global:DefaultDomain -and $Global:DefaultDomain.Length -gt 0)
        $btn.IsEnabled = ($hasName -and $hasEmailOrDomain)
    } catch {}
}

function New-AppUser {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param()
    if (-not $Global:IsConnected) {
        Show-ErrorMessage "Please connect to Microsoft Graph first"
        return
    }
    try {
        Initialize-Module -Modules @("Microsoft.Graph.Users")
        $nameBox = $Window.FindName("NewUserNameTextBox")
        $mailBox = $Window.FindName("NewUserEmailTextBox")
        if (-not $nameBox -or -not $mailBox) {
            Show-ErrorMessage "New user input controls not found"
            return
        }
        $displayName = ($nameBox.Text).Trim()
        $emailInput  = ($mailBox.Text).Trim()

        if (-not $displayName) {
            Show-ErrorMessage "Display Name is required"
            return
        }

        # Determine default domain if needed
        if (-not $Global:DefaultDomain) { $Global:DefaultDomain = Get-DefaultDomainName }

        # Build email/UPN
        $upn = $null
        if ([string]::IsNullOrWhiteSpace($emailInput)) {
            if (-not $Global:DefaultDomain) {
                Show-ErrorMessage "Email is empty and default domain could not be determined"
                return
            }
            $local = ($displayName.ToLower() -replace '[^a-z0-9\s\-\.]', '' -replace '\s+', '.' -replace '\.+', '.').Trim('.')
            if (-not $local) { $local = "user" + (Get-Random -Maximum 9999) }
            $upn = "{0}@{1}" -f $local, $Global:DefaultDomain
        } elseif ($emailInput -notmatch '@') {
            if (-not $Global:DefaultDomain) {
                Show-ErrorMessage "Email missing domain and default domain could not be determined"
                return
            }
            $upn = "{0}@{1}" -f $emailInput, $Global:DefaultDomain
        } else {
            $upn = $emailInput
        }

        $mailNickname = ($upn.Split('@')[0])

        # Generate a temporary password
        $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789@$!#%*?&"
        $TempPassword = -join (1..16 | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })

        Write-Host ("Creating user '{0}' with UPN '{1}'..." -f $displayName, $upn) -ForegroundColor Yellow
        try {
            New-MgUser -AccountEnabled:$true `
                       -DisplayName $displayName `
                       -UserPrincipalName $upn `
                       -MailNickname $mailNickname `
                       -PasswordProfile @{ Password = $TempPassword; ForceChangePasswordNextSignIn = $true } `
                       -ErrorAction Stop | Out-Null

            Show-SuccessMessage ("User created:`nName: {0}`nUPN: {1}`nTemp Password: {2}`n(User must change at first sign-in)" -f $displayName, $upn, $TempPassword)
            Write-Host "User created successfully" -ForegroundColor Green
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match "Insufficient privileges" -or $msg -match "Authorization" -or $msg -match "Forbidden" -or $msg -match "requires one of the following scopes") {
                Show-ErrorMessage "Creating users requires Graph delegated permission 'User.ReadWrite.All' with admin consent."
            } else {
                Show-ErrorMessage ("Failed to create user: {0}" -f $msg)
            }
            return
        }
    }
    catch {
        Show-ErrorMessage ("Create user error: {0}" -f $_.Exception.Message)
    }
}

# Navigation event handlers
function Show-AdminSection {
    Update-NavigationButton -ActiveSection "Admin"
    if ($Global:IsConnected) {
        Get-AdminOverview
    }
}

function Show-EntraSection {
    Update-NavigationButton -ActiveSection "Entra"
    if ($Global:IsConnected) {
        Set-DefaultDomainHint
        Update-CreateUserButtonState
        Get-EntraIdStatistic
    }
}

function Show-IntuneSection {
    Update-NavigationButton -ActiveSection "Intune"
    if ($Global:IsConnected) {
        Get-IntuneStatistic
    }
}

function Show-SecuritySection {
    Update-NavigationButton -ActiveSection "Security"
    if ($Global:IsConnected) {
        Get-SecurityStatistic
    }
}

# Main application function
function Start-GraphApp {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    if (-not $PSCmdlet.ShouldProcess("Strata365","Start application UI")) { return }
    try {
        # Load XAML
        $XamlPath = Join-Path $PSScriptRoot "MainWindow.xaml"
        if (-not (Test-Path $XamlPath)) {
            throw "XAML file not found: $XamlPath"
        }
        
        $Xaml = Get-Content $XamlPath -Raw
        $Xaml = $Xaml -replace 'x:Class=".*?"', ''
        
        # Create window
        $Global:Window = [Windows.Markup.XamlReader]::Parse($Xaml)
        
        # Bind logo image from file if present
        try {
            $logoControl = $Window.FindName("AppLogo")
            if ($logoControl) {
                $logoPath = Join-Path $PSScriptRoot "Strata365Logo2.png"
                if (Test-Path $logoPath) {
                    $bi = New-Object System.Windows.Media.Imaging.BitmapImage
                    $bi.BeginInit()
                    $bi.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                    $bi.UriSource = New-Object System.Uri($logoPath, [System.UriKind]::Absolute)
                    $bi.EndInit()
                    try { $bi.Freeze() } catch {}
                    $logoControl.Source = $bi
                }
            }
        } catch {}
        
        # Wire up event handlers
        $Window.FindName("ConnectButton").Add_Click({ Connect-WithCredential })
        $Window.FindName("DisconnectButton").Add_Click({ Disconnect-FromGraph })
        
        # Window control handlers
        $Window.FindName("MinimizeButton").Add_Click({ $Window.WindowState = "Minimized" })
        $Window.FindName("MaximizeButton").Add_Click({ 
            if ($Window.WindowState -eq "Maximized") {
                $Window.WindowState = "Normal"
            } else {
                $Window.WindowState = "Maximized"
            }
        })
        $Window.FindName("CloseButton").Add_Click({ $Window.Close() })
        
        # Navigation event handlers
        $Window.FindName("AdminButton").Add_Click({ Show-AdminSection })
        $Window.FindName("EntraButton").Add_Click({ Show-EntraSection })
        $Window.FindName("IntuneButton").Add_Click({ Show-IntuneSection })
        $Window.FindName("SecurityButton").Add_Click({ Show-SecuritySection })
        
        # Entra: data loaders and actions
        $Window.FindName("RefreshEntraStatsButton").Add_Click({ Get-EntraIdStatistic })
        $Window.FindName("LoadUsersButton").Add_Click({ Get-EntraUser -ComboName "UserSearchComboBox" })
        $Window.FindName("LoadUserButton").Add_Click({ Show-SelectedUserProfile })
        $Window.FindName("LoadMfaUsersButton").Add_Click({ Get-EntraUser -ComboName "MfaUserComboBox" })
        $Window.FindName("CreateUserButton").Add_Click({ New-AppUser })
        $Window.FindName("NewUserNameTextBox").Add_TextChanged({ Update-CreateUserButtonState })
        $Window.FindName("NewUserEmailTextBox").Add_TextChanged({ Update-CreateUserButtonState })
        Register-EmailAutoDomain
        
        # Initialize with Admin section
        Update-NavigationButton -ActiveSection "Admin"
        
        # Show window
        Write-Host "Starting Strata365 with MSAL.NET..." -ForegroundColor Cyan
        $Window.ShowDialog() | Out-Null
    }
    catch {
        Write-Error "Failed to start application: $($_.Exception.Message)"
        Show-ErrorMessage "Failed to start application: $($_.Exception.Message)"
    }
}

# Ensure required modules (auto-install if missing)
Initialize-Module -Modules @(
    "Microsoft.Graph.Authentication",
    "ExchangeOnlineManagement"
)

# Start the application
Start-GraphApp
