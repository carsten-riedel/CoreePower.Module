function EnsureModule {
    [alias("cpem")] 
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName,
        [Parameter(Mandatory)]
        [string]$ModuleVersion
    )

    #Get module in the current session
    $ModuleAvailableInSession = Get-Module -Name $ModuleName | Where-Object {$_.Version -ge $ModuleVersion}

    if ($ModuleAvailableInSession) {
        return
    }
    else {
        $ModuleAvailableOnSystem = Get-Module -Name $ModuleName -ListAvailable | Where-Object {$_.Version -ge $ModuleVersion}
        
        if ($ModuleAvailableOnSystem) {
            Import-Module -Name $ModuleName -MinimumVersion $ModuleVersion
        } else {
            Install-Module -Name $ModuleName -RequiredVersion $ModuleVersion -Force -AllowClobber
            Import-Module -Name $ModuleName -MinimumVersion $ModuleVersion
        }
    }
}

EnsureModule -ModuleName "CoreePower.Lib" -ModuleVersion "0.0.0.21"


function PublishModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cppm")]   
    param(
        [string] $Path = ""
    )

    if ($Path -eq "")
    {
        $loc = Get-Location
        $Path = $loc.Path
    }

    $Path = $Path.TrimEnd('\')

    $LastDirectory = Split-Path -Path $Path -Leaf
    $psd1BaseName = Get-ChildItem -Path $Path | Where-Object { $_.Extension -eq ".psd1" } | Select-Object BaseName
    $psm1BaseName = Get-ChildItem -Path $Path | Where-Object { $_.Extension -eq ".psm1" } | Select-Object BaseName

    if($psd1BaseName.Count -eq 0)
    {
        Write-Error "Error: no powerShell module manifest files found. Please ensure that there is one .psd1 file in the directory and try again."
        return
    }

    if($psm1BaseName.Count -eq 0)
    {
        Write-Error "Error: no root module files found. Please ensure that there is one .psm1 file in the directory and try again."
        return
    }

    if($psd1BaseName.Count -gt 1)
    {
        Write-Error "Error: multiple module definition files found. Please ensure that there is only one .psd1 file in the directory and try again."
        return
    }

    if($psm1BaseName.Count -gt 1)
    {
        Write-Error "Error: multiple module definition files found. Please ensure that there is only one .psm1 file in the directory and try again."
        return
    }

    if($LastDirectory -eq $psd1BaseName -and $psd1BaseName -eq $psm1BaseName)
    {
        Write-Error "Error: The parent directory name, .psd1 filename, and .psm1 filename must all be identical. Please ensure that all three names match and try again."
        return
    }


    $keyFileFullName = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.Name -eq ".key" } | Select-Object FullName
    if($null -eq $keyFileFullName)
    {
        Write-Error  "Error: A .key file containing the NuGet API key is missing from the publish directory. Please add the file and try again."
        return
    }

    $gitignoreFullName = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.Name -eq ".gitignore" } | Select-Object FullName
    if($null -eq $gitignoreFullName)
    {
        Write-Warning  "Warning: A .gitignore file is not present, the NuGet API key may be exposed in the publish directory. Please include a .gitignore file with ignore statements for the key to prevent unauthorized access."
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $PackageProviderModule = Get-InstalledModule -Name PackageManagement -MinimumVersion 1.4.8.1 -ErrorAction SilentlyContinue
    $PowerShellGetModule = Get-InstalledModule -Name PowerShellGet -MinimumVersion 2.2.5 -ErrorAction SilentlyContinue

    if (!$PackageProviderModule -or !$PowerShellGetModule) {
        # Either or both modules are missing or have a lower version, so install/update them
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
        Install-Module PowerShellGet -AllowClobber -Force -Scope CurrentUser | Out-Null
        Write-Error  "Error: The PackageManagement or PowerShellGet modules were outdated in the user scope and have been updated. Please close and reopen your PowerShell session and try again."
        return
    }

    [string]$NuGetAPIKey = Get-Content -Path "$($keyFileFullName.FullName)"

    Publish-Module -Path "$Path" -NuGetApiKey "$NuGetAPIKey" -Repository "PSGallery" -Verbose

}

function Merge-Hashtable($target, $source) {
    $source.Keys | ForEach-Object {
        $key = $_
        if (-not $target.ContainsKey($key)) {
            # Add new key-value pairs
            $target[$key] = $source[$key]
        } elseif ($target[$key] -eq '' -and $source[$key] -ne '') {
            # Overwrite the value when target key's value is empty
            $target[$key] = $source[$key]
        } elseif ($source[$key] -is [Hashtable]) {
            # Merge nested hashtables
            Merge-Hashtable $target[$key] $source[$key]
        }
    }
}

# Modify Merge-Object function to handle nested hashtables
function Merge-Object($target, $source) {
    $source.PSObject.Properties | ForEach-Object {
        $propertyName = $_.Name
        $propertyValue = $_.Value

        if ($target.PSObject.Properties.Name.Contains($propertyName)) {
            if ($propertyValue -is [PSCustomObject]) {
                # Initialize the target property if it's null
                if ($null -eq $target.$propertyName) {
                    $target.$propertyName = [PSCustomObject]@{}
                }
                Merge-Object $target.$propertyName $propertyValue
            } elseif ($propertyValue -is [Array]) {
                # Merge arrays
                $target.$propertyName += $propertyValue
            } elseif ($propertyValue -is [Hashtable]) {
                # Merge hashtables
                if ($null -eq $target.$propertyName) {
                    $target.$propertyName = @{}
                }
                Merge-Hashtable $target.$propertyName $propertyValue
            }
        } else {
            $target | Add-Member -MemberType $_.MemberType -Name $propertyName -Value $propertyValue
        }
    }
}




function UpdateModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cpum")]
    param(
        [string] $Path = ""
    )

    if ($Path -eq "")
    {
        $loc = Get-Location
        $Path = $loc.Path
    }

    $Path = $Path.TrimEnd('\')

    $psd1BaseName = Get-ChildItem -Path $Path | Where-Object { $_.Extension -eq ".psd1" } | Select-Object FullName

    if($psd1BaseName.Count -eq 0)
    {
        Write-Error "Error: no powerShell module manifest files found. Please ensure that there is one .psd1 file in the directory and try again."
        return
    }

    if($psd1BaseName.Count -gt 1)
    {
        Write-Error "Error: multiple module definition files found. Please ensure that there is only one .psd1 file in the directory and try again."
        return
    }

    $fileContent = Get-Content -Path "$($psd1BaseName.FullName)" -Raw
    $index = $fileContent.IndexOf("@{")
    if($index -ne -1){
        $fileContent = $fileContent.Substring(0, $index) + $fileContent.Substring($index + 2)
    }
    $index = $fileContent.LastIndexOf("}")
    if($index -ne -1){
        $fileContent = $fileContent.Substring(0, $index) + $fileContent.Substring($index + 2)
    }

    $Data  = Invoke-Expression "[PSCustomObject]@{$fileContent}"

    $ver = [Version]$Data.ModuleVersion
    $newver = [Version]::new($ver.Major, $ver.Minor, $ver.Build, ($ver.Revision + 1))
    $Data.ModuleVersion = [string]$newver
    $Data.PrivateData.PSData.LicenseUri = $Data.PrivateData.PSData.LicenseUri.Replace($ver, $newver)

    $psd1layoutx = [pscustomobject]@{
        RootModule = ''
        ModuleVersion = ''
        CompatiblePSEditions = @()
        GUID = ''
        Author = ''
        CompanyName = ''
        Copyright = ''
        Description = ''
        PowerShellVersion = ''
        PowerShellHostName = ''
        PowerShellHostVersion = ''
        DotNetFrameworkVersion = ''
        CLRVersion = ''
        ProcessorArchitecture = ''
        RequiredModules = @()
        RequiredAssemblies = @()
        ScriptsToProcess = @()
        TypesToProcess = @()
        FormatsToProcess = @()
        NestedModules = @()
        FunctionsToExport = @()
        CmdletsToExport = @()
        VariablesToExport = ''
        AliasesToExport = @()
        DscResourcesToExport = @()
        ModuleList = @()
        FileList = @()
        PrivateData = @{PSData = @{
                LicenseUri = ''
                Tags = ' '
                ProjectUri = ''
                IconUri = ''
                ReleaseNotes = ''
            }}
        HelpInfoURI = ''
        DefaultCommandPrefix = ''
    }

    # Merge the properties of the second object into the combined object
    Merge-Object $Data $psd1layoutx 

    New-ModuleManifest `
    -Path "$($psd1BaseName.FullName)" `
    -GUID "$($Data.GUID)" `
    -Description "$($Data.Description)" `
    -LicenseUri "$($Data.PrivateData.PSData.LicenseUri)" `
    -FunctionsToExport $Data.FunctionsToExport `
    -AliasesToExport $Data.AliasesToExport  `
    -ModuleVersion "$($Data.ModuleVersion)" `
    -RootModule "$($Data.RootModule)" `
    -Author "$($Data.Author)" `
    -RequiredModules $Data.RequiredModules  `
    -CompanyName "$($Data.CompanyName)"  `
    -Tags $($Data.PrivateData.PSData.Tags)
    
}

$psd1layout = [pscustomobject]@{
    RootModule = ''
    ModuleVersion = ''
    CompatiblePSEditions = @()
    GUID = ''
    Author = ''
    CompanyName = ''
    Copyright = ''
    Description = ''
    PowerShellVersion = ''
    PowerShellHostName = ''
    PowerShellHostVersion = ''
    DotNetFrameworkVersion = ''
    CLRVersion = ''
    ProcessorArchitecture = ''
    RequiredModules = @()
    RequiredAssemblies = @()
    ScriptsToProcess = @()
    TypesToProcess = @()
    FormatsToProcess = @()
    NestedModules = @()
    FunctionsToExport = @()
    CmdletsToExport = @()
    VariablesToExport = ''
    AliasesToExport = @()
    DscResourcesToExport = @()
    ModuleList = @()
    FileList = @()
    PrivateData = @{PSData = @{
            LicenseUri = ''
            Tags = @()
            ProjectUri = ''
            IconUri = ''
            ReleaseNotes = ''
        }}
    HelpInfoURI = ''
    DefaultCommandPrefix = ''
}

#CreateModule -Path "C:\temp" -ModuleName "CoreePower.Module" -Description "Library for module management" -Author "Carsten Riedel"
function CreateModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cpcm")]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Author,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey
    )

    if ($Path -eq "")
    {
        $loc = Get-Location
        $Path = $loc.Path
    }

    $Path = $Path.TrimEnd('\')

    #$psd1BaseName = Get-ChildItem -Path $Path | Where-Object { $_.Extension -eq ".psd1" } | Select-Object FullName

    # Check if the directory exists
    if(!(Test-Path $Path)){
        # Create the directory if it does not exist
        New-Item -ItemType Directory -Path $Path  | Out-Null
    }

    # Check if the directory exists
    if(!(Test-Path "$Path\$ModuleName")){
        # Create the directory if it does not exist
        New-Item -ItemType Directory -Path "$Path\$ModuleName" | Out-Null
    }

    $licenceValue  = @"
    MIT License

    Copyright (c) $((Get-Date).Year) $Author
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"@

    $psm1Value  = @"
<#
    $ModuleName root module
#>

Import-Module -Name "Other.Module" -MinimumVersion "0.0.0.1"

. `"`$PSScriptRoot\$ModuleName.ps1`"

"@

    $ps1Value  = @"

function SampleFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("sf")]
    param()
    Write-Output "Hello World!"
}

"@

    Set-Content -Path "$Path\$ModuleName\LICENSE.txt" -Value "$licenceValue"
    Set-Content -Path "$Path\$ModuleName\$ModuleName.psm1" -Value "$psm1Value"
    Set-Content -Path "$Path\$ModuleName\$ModuleName.ps1" -Value "$ps1Value"
    Set-Content -Path "$Path\$ModuleName\.key" -Value "$ApiKey"
    Set-Content -Path "$Path\$ModuleName\.gitignore" -Value ".key"
<#
    $psd1layout.Author = "$Author"
    $psd1layout.RootModule = "$ModuleName.psm1"
    $psd1layout.CompanyName = "$Author"
    $psd1layout.Copyright = "(c) 2023 $Author. All rights reserved."
    $psd1layout.Description = $Description
    $psd1layout.GUID = (New-Guid).ToString()
    $psd1layout.FunctionsToExport = @("SampleFunction")
    $psd1layout.AliasesToExport = @("sf")
    $psd1layout.ModuleVersion = "0.0.0.1"
    $psd1layout.RequiredModules = @(@{ ModuleName = 'Other.Module' ; ModuleVersion = '0.0.0.1' })
    $psd1layout.PrivateData.PSData.LicenseUri = "https://www.powershellgallery.com/packages/$ModuleName/0.0.0.1/Content/LICENSE.txt"
    $psd1layout.PrivateData.PSData.Tags = @("example","module")
#>
    New-ModuleManifest `
    -Path "$Path\$ModuleName\$ModuleName.psd1" `
    -GUID "$((New-Guid).ToString())" `
    -Description "$Description" `
    -LicenseUri "https://www.powershellgallery.com/packages/$ModuleName/0.0.0.1/Content/LICENSE.txt" `
    -FunctionsToExport @("SampleFunction") `
    -AliasesToExport @("sf")  `
    -ModuleVersion "0.0.0.1" `
    -RootModule "$ModuleName.psm1" `
    -Author "$Author" `
    -RequiredModules @(@{ ModuleName = 'Other.Module' ; ModuleVersion = '0.0.0.1' })  `
    -CompanyName "$Author" `
    -Tags @("empty","module")

    (Get-Content -path "$Path\$ModuleName\$ModuleName.psd1") | Set-Content -Encoding default -Path "$Path\$ModuleName\$ModuleName.psd1"

<#
    $towrite = ConvertToExpression -InputObject $psd1layout

    $towrite = $towrite -replace "^\[pscustomobject\]", ""

    if (-not($null -eq $towrite))
    {
        # Write the string to a file
        Set-Content -Path "$Path\$ModuleName\$ModuleName.psd1" -Value $towrite
    }
    #>
}

#CreateModule -Path "C:\temp" -ModuleName "CoreePower.Module" -Description "Library for module management" -Author "Carsten Riedel" 
#UpdateModuleVersion -Path "C:\temp\CoreePower.Module"

function RemoveOldModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cprmo")]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $retval = @()

    $localModules = (Get-Module -ListAvailable $Name) | Sort-Object Version -Descending

    if( ($localModules -is [system.array]) -or ($null -ne $localModules))
    {
        foreach($item in $localModules)
        {
            if (($item.ModuleBase -Like "*$env:ProgramFiles*") -or ($item.ModuleBase -Like "*$env:ProgramW6432*"))
            {
                $Type = "System"
            }
            else {
                $Type = "User"
            }

            $retval += [PSCustomObject]@{ Name = $item.Name; Version = $item.Version; Type = $Type ;Path = $item.ModuleBase.TrimEnd($item.Version.ToString()).TrimEnd('\').TrimEnd($item.Name).TrimEnd('\') ;Obj = $item }
        }
    }
    else {

        Write-Warning "$Name could not be found please check the name."
        return
    }

    $UserModules = @($retval | Where-Object {$_.Type -eq "User"} | Sort-Object Version -Descending)
    $MachineModules = @($retval | Where-Object {$_.Type -eq "System"} | Sort-Object Version -Descending)

    $IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsAdmin)
    {
        if ($UserModules.Count -ge 1)
        {
            for ($i = 1; $i -lt $UserModules.Count; $i++) {
                $DirVers = "$($UserModules[$i].Path)\$($UserModules[$i].Name)\$($UserModules[$i].Version)"
                Remove-Item -Recurse -Force -Path $DirVers
                Write-Host "User rights removed user module:" $UserModules[$i].Name $UserModules[$i].Version
            }
        }
    }
    else {
        if ($MachineModules.Count -ge 1)
        {
            for ($i = 1; $i -lt $MachineModules.Count; $i++) {
                $DirVers = "$($MachineModules[$i].Path)\$($MachineModules[$i].Name)\$($MachineModules[$i].Version)"
                Remove-Item -Recurse -Force -Path $DirVers
                Write-Host "Admin rights removed admin module:" $MachineModules[$i].Name $MachineModules[$i].Version
            }
        }
        if ($UserModules.Count -gt 0 -and $MachineModules.Count -gt 0)
        {
            if ($MachineModules[0].Version -ge $UserModules[0].Version)
            {
                for ($i = 0; $i -lt $UserModules.Count; $i++) {
                    $DirVers = "$($UserModules[$i].Path)\$($UserModules[$i].Name)\$($UserModules[$i].Version)"
                    Remove-Item -Recurse -Force -Path $DirVers
                    Write-Host "Admin rights removed user module:" $UserModules[$i].Name $UserModules[$i].Version
                }
            }
        }
    }
}

function ListModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cplm")]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    Write-Output "List the currently installed modules versions on your computer.`n"
    Get-Module -ListAvailable "$Name" | Format-Table -AutoSize

    Write-Output "Displays function/commands loaded in your current session.`n"
    Get-Command -Module "$Name" -All | Sort-Object -Property @{Expression = 'Source' ; Ascending = $true }, @{ Expression = 'Version' ; Descending = $true}, @{ Expression = 'CommandType' ; Descending = $true} | Select-Object Source, Version , CommandType , Name | Format-Table -AutoSize

    Write-Output "Displays the latest online version available.`n"
    #Find-Module -Name "$Name"
}

function CoreePower {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cpcp")]
    param()

    $me = "CoreePower*"

    $Install=@('PowerShellGet', "$me") ; try { Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force } catch {} 
    $nugetProvider = Get-PackageProvider -ListAvailable | Where-Object Name -eq "nuget"; if (-not($nugetProvider -and $nugetProvider.Version -ge "2.8.5.201")) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null }
    
    $updateable = Find-Module -Name $Install -Repository PSGallery | Select-Object Name,Version | Where-Object { -not (Get-Module -ListAvailable -Name $_.Name | Sort-Object Version -Descending | Select-Object -First 1 | Where-Object Version -eq $_.Version) }
    $updateDone = $false

    foreach($item in $updateable)
    {
        Write-Output "Installing user module: $($item.Name) $($item.Version)" 
        Install-Module -Name $item.Name -RequiredVersion $item.Version -Scope CurrentUser -Force -AllowClobber
        Write-Output "Importing user module: $($_.Name) $($item.Version)"
        Import-Module -Name $item.Name -MinimumVersion $item.Version
        $updateDone = $true
    }

    if ($updateDone)
    {
        Write-Output "Updates have been applied. Please restart your PowerShell session to ensure that the changes take effect."
    }

    $localModules = (Get-Module -ListAvailable "$me") | Sort-Object Version -Descending

    $localModules = $localModules | Group-Object Name

    foreach($groups in $localModules)
    {
        $retval = @()

        foreach ($item in $groups.Group)
        {
            if( ($groups.Group -is [system.array]) -or ($null -ne $groups.Group))
            {
                if (-not(($item.ModuleBase -Like "*$env:ProgramFiles*") -or ($item.ModuleBase -Like "*$env:ProgramW6432*")))
                {
                    $retval += [PSCustomObject]@{ Name = $item.Name; Version = $item.Version; Path = $item.ModuleBase.TrimEnd($item.Version.ToString()).TrimEnd('\').TrimEnd($item.Name).TrimEnd('\') ;Obj = $item }
                }
            }
        }

        $UserModules = @($retval | Sort-Object Version -Descending)
       
        if ($UserModules.Count -ge 1)
        {
            for ($i = 1; $i -lt $UserModules.Count; $i++) {
                $DirVers = "$($UserModules[$i].Path)\$($UserModules[$i].Name)\$($UserModules[$i].Version)"
                Remove-Item -Recurse -Force -Path $DirVers
                Write-Host "Removed old user module:" $UserModules[$i].Name $UserModules[$i].Version
            }
        }
    }
}


<#
function Expand-NuGetPackage {
    param(
        [string]$nugetPackageName,
        [string]$extractPath
    )

    # Check if NuGet package source is registered
    $nugetSource = Get-PackageSource -Name "NuGet" -ErrorAction SilentlyContinue
    if (-not $nugetSource) {
        Register-PackageSource -Name "NuGet" -Location "https://api.nuget.org/v3/index.json" -ProviderName NuGet
    }

    # Install NuGet.CommandLine package
    $package = Get-Package -Name $nugetPackageName -ProviderName NuGet -Scope CurrentUser -ErrorAction SilentlyContinue
    if (-not $package) {
        Install-Package -Name $nugetPackageName -ProviderName NuGet -Scope CurrentUser -Force
        $package = Get-Package -Name $nugetPackageName -ProviderName NuGet -Scope CurrentUser -ErrorAction SilentlyContinue
    }
    $packagePath = $package | Select-Object -ExpandProperty Source

    # Extract package to temp directory
    $tempPath = [System.IO.Path]::GetTempFileName() + ".zip"
    Copy-Item $packagePath $tempPath
    Rename-Item $tempPath -NewName "$tempPath.zip"
    if (-not (Test-Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath | Out-Null
    }
    Expand-Archive -Path "$tempPath.zip" -DestinationPath $extractPath -Force
    Remove-Item "$tempPath.zip"
}

function Copy-SubfoldersToDestination2 {
    param (
        [string]$SourceFolder,
        [string[]]$Subfolders,
        [string]$DestinationFolder
    )

    foreach ($subfolder in $Subfolders) {
        $subfolderPath = Join-Path $SourceFolder $subfolder

        Copy-Item $subfolderPath -Destination $DestinationFolder -Recurse -Force
    }
}

function Copy-SubfoldersToDestination {
    param (
        [string]$SourceFolder,
        [string[]]$Subfolders,
        [string]$DestinationFolder
    )

    foreach ($subfolder in $Subfolders) {
        $subfolderPath = Join-Path $SourceFolder $subfolder
        Get-ChildItem $subfolderPath -Recurse | 
            Where-Object {!$_.PSIsContainer} | 
            Copy-Item -Destination $DestinationFolder -Force
    }
}


Expand-NuGetPackage -nugetPackageName "Coree.NuPack" -extractPath "C:\temp\foox"
Copy-SubfoldersToDestination -Subfolders @('tools','ProjectPath') -SourceFolder "C:\temp\foox" -DestinationFolder 'C:\temp\yo'
#>


################################################################################


<#
$owner = "carsten-riedel"
$repo = "CoreePower.Config"
$path = "."


$url = "https://api.github.com/repos/$owner/$repo/contents/$path"
$response = Invoke-RestMethod -Uri $url -Method Get

foreach ($file in $response) {
    Write-Host $file.name
}

function Get-GitHubDirectoryContents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Owner,
        [Parameter(Mandatory = $true)]
        [string]$Repo,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$Ref = 'master'
    )

    $uri = "https://api.github.com/repos/$($Owner)/$($Repo)/contents/$($Path)?ref=$($Ref)"
    $response = Invoke-RestMethod -Uri $uri

    foreach ($item in $response) {
        if ($item.type -eq 'dir') {
            # Recursively get contents of subdirectory
            Get-GitHubDirectoryContents -Owner $Owner -Repo $Repo -Path $item.path -Ref $Ref
        }
        else {
            # Output file path
            Write-Output $item.path
        }
    }
}

function Get-GitHubFileContent {
    param (
        [string]$Owner,
        [string]$Repo,
        [string]$Path,
        [string]$Branch = 'main'
    )

    $url = "https://api.github.com/repos/$Owner/$Repo/contents/$($Path)?ref=$($Branch)"

    $response = Invoke-RestMethod -Method Get -Uri $url

    if ($response.type -eq 'file') {
        $content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.content))
        return $content
    }
    else {
        Write-Error 'The specified path does not point to a file.'
    }
}


Get-GitHubDirectoryContents -Repo $repo -Owner $owner -Path $path -Ref "main"
Get-GitHubFileContent -Repo $repo -Owner $owner -Path "src/CoreePower.Config/CoreePower.Config.EnviromentVariable.ps1" -Branch "main"
#>