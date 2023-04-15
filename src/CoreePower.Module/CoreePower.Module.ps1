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

    Initialize-PowerShellGetLatest
    Initialize-PackageManagementLatest

    [string]$NuGetAPIKey = Get-Content -Path "$($keyFileFullName.FullName)"

    Publish-Module -Path "$Path" -NuGetApiKey "$NuGetAPIKey" -Repository "PSGallery" -Verbose

}

function PublishModule2 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
    [alias("cppm2")]   
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

    Initialize-PowerShellGetLatest
    Initialize-PackageManagementLatest

    [string]$NuGetAPIKey = Get-Content -Path "$($keyFileFullName.FullName)"

    
    $fullname = Get-ChildItem -Path $Path | Where-Object { $_.Extension -eq ".psd1" }

    $fileContent = Get-Content -Path "$($fullname.FullName)" -Raw
    $index = $fileContent.IndexOf("@{")
    if($index -ne -1){
        $fileContent = $fileContent.Substring(0, $index) + $fileContent.Substring($index + 2)
    }
    $index = $fileContent.LastIndexOf("}")
    if($index -ne -1){
        $fileContent = $fileContent.Substring(0, $index) + $fileContent.Substring($index + 2)
    }

    $Data  = Invoke-Expression "[PSCustomObject]@{$fileContent}"

    try {
        Publish-Module -Path "$Path" -NuGetApiKey "$NuGetAPIKey" -Repository "PSGallery" -Verbose

        $executable = Get-Command "git" -ErrorAction SilentlyContinue

        if ($executable) {
            Write-Host "Git executable found at $($executable.Source) add, all commit and push"
            &git -C "$Path" add -A ./
            &git -C "$Path" commit -m "Publish $([System.IO.Path]::GetFileNameWithoutExtension($Data.RootModule)) $($Data.ModuleVersion)" 
            &git -C "$Path" push 
        }
        else {
            Write-Host "Git executable not found in PATH environment variable."
        }
    }
    catch {
        Write-Error "Failed to publish module: $($_.Exception.Message)"
    }

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

function Convert-JsonToPowerShellNotation {
    [alias("cjpn")] 
    param (
        [Parameter(Mandatory=$true)]
        [string]$JsonString
    )

    function Convert-ObjectToPowerShellNotation {
        param (
            [Parameter(Mandatory=$true)]
            [PSObject]$InputObject
        )

        $outputString = '@{ '

        foreach ($property in $InputObject.PSObject.Properties) {
            $key = $property.Name
            $value = $property.Value

            if ($value -is [string]) {
                $outputString += "$key = '$value'; "
            } elseif ($value -is [bool]) {
                $outputString += "$key = $([bool]::ToString($value).ToLower()); "
            } elseif ($value -is [array]) {
                $outputString += "$key = @($(Convert-ArrayToPowerShellNotation -InputArray $value)); "
            } else {
                $outputString += "$key = $(Convert-ObjectToPowerShellNotation -InputObject $value); "
            }
        }

        $outputString = $outputString.TrimEnd('; ')
        $outputString += ' }'

        return $outputString
    }

    function Convert-ArrayToPowerShellNotation {
        param (
            [Parameter(Mandatory=$true)]
            [array]$InputArray
        )

        $outputString = ""

        foreach ($element in $InputArray) {
            if ($element -is [string]) {
                $outputString += "'$element', `n"
            } elseif ($element -is [bool]) {
                $outputString += "$([bool]::ToString($element).ToLower()), `n"
            } elseif ($element -is [array]) {
                $outputString += "@($(Convert-ArrayToPowerShellNotation -InputArray $element)), `n"
            } else {
                $outputString += "$(Convert-ObjectToPowerShellNotation -InputObject $element), `n"
            }
        }

        $outputString = $outputString.TrimEnd(', ')

        return $outputString
    }

    try {
        $PowerShellObject = $JsonString | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to convert JSON string to PowerShell object. Please ensure the input is a valid JSON string."
        return
    }

    if ($PowerShellObject -is [array]) {
        return "@($(Convert-ArrayToPowerShellNotation -InputArray $PowerShellObject))"
    } else {
        return (Convert-ObjectToPowerShellNotation -InputObject $PowerShellObject)
    }
}

function Convert-JsonToPowerShellNotation2 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$JsonString
    )

    function Convert-ObjectToPowerShellNotation2 {
        param (
            [Parameter(Mandatory=$true)]
            [PSObject]$InputObject,
            [int]$Indent = 0
        )

        $indentation = " " * $Indent
        $outputString = "@{" + [Environment]::NewLine

        foreach ($property in $InputObject.PSObject.Properties) {
            $key = $property.Name
            $value = $property.Value

            if ($value -is [string]) {
                $outputString += "$indentation$key = '$value';" + [Environment]::NewLine
            } elseif ($value -is [bool]) {
                $outputString += "$indentation$key = $([bool]::ToString($value).ToLower());" + [Environment]::NewLine
            } elseif ($value -is [array]) {
                $outputString += "$indentation$key = @(" + [Environment]::NewLine
                $outputString += "$(Convert-ArrayToPowerShellNotation2 -InputArray $value -Indent ($Indent + 4))" + [Environment]::NewLine
                $outputString += "$indentation);" + [Environment]::NewLine
            } else {
                $outputString += "$indentation$key = $(Convert-ObjectToPowerShellNotation2 -InputObject $value -Indent ($Indent + 4));" + [Environment]::NewLine
            }
        }

        $outputString += $indentation + '}'

        return $outputString
    }

    function Convert-ArrayToPowerShellNotation2 {
        param (
            [Parameter(Mandatory=$true)]
            [array]$InputArray,
            [int]$Indent = 0
        )

        $indentation = " " * $Indent
        $outputString = ""

        foreach ($element in $InputArray) {
            if ($element -is [string]) {
                $outputString += $indentation + "'$element'," + [Environment]::NewLine
            } elseif ($element -is [bool]) {
                $outputString += $indentation + "$([bool]::ToString($element).ToLower())," + [Environment]::NewLine
            } elseif ($element -is [array]) {
                $outputString += $indentation + "@(" + [Environment]::NewLine
                $outputString += "$(Convert-ArrayToPowerShellNotation2 -InputArray $element -Indent ($Indent + 4))" + [Environment]::NewLine
                $outputString += $indentation + ")," + [Environment]::NewLine
            } else {
                $outputString += $indentation + "$(Convert-ObjectToPowerShellNotation2 -InputObject $element -Indent ($Indent + 4))," + [Environment]::NewLine
            }
        }

        $outputString = $outputString.TrimEnd(",`n")

        return $outputString
    }

    try {
        $PowerShellObject = $JsonString | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to convert JSON string to PowerShell object. Please ensure the input is a valid JSON string."
        return
    }
    
    if ($PowerShellObject -is [array]) {
        return "@(`n$(Convert-ArrayToPowerShellNotation2 -InputArray $PowerShellObject)`n)"
    } else {
        return (Convert-ObjectToPowerShellNotation2 -InputObject $PowerShellObject)
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
    -Tags $($Data.PrivateData.PSData.Tags) `
    -CmdletsToExport '' `
    -VariablesToExport ''

    #(Get-Content -path "$Path\$ModuleName\$ModuleName.psd1") | Set-Content -Encoding default -Path "$Path\$ModuleName\$ModuleName.psd1"
    
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


<#

$roots = @("C:\temp", "C:\Windows") ; $roots | ForEach-Object { Get-ChildItem -Path $_ -Filter "nuget*" -Recurse -ErrorAction SilentlyContinue } | Where-Object {!$_.PSIsContainer} | Select-Object -ExpandProperty FullName

$roots = @("D:\", "E:\") ; $roots | ForEach-Object { Get-ChildItem -Path $_ -Include @("*.mkv","*.mp4") -Recurse -ErrorAction SilentlyContinue } | Where-Object {!$_.PSIsContainer -and $_.Length -gt 1000000 } | Select-Object -ExpandProperty FullName

$roots = @("C:\","D:\", "E:\") ; $roots | ForEach-Object { Get-ChildItem -Path $_ -Include @("*.txt","*.md") -Recurse -ErrorAction SilentlyContinue } | Where-Object {!$_.PSIsContainer -and $_.Length -lt 10000 } | Where-Object { (Get-Content $_.FullName -Raw) -match "hello" } | Select-Object -ExpandProperty FullName

$roots = @("$($env:USERPROFILE)\source\repos", "C:\VCS" , "C:\base") ; $roots | ForEach-Object { Get-ChildItem -Path $_ -Include @("*.cs") -Recurse -ErrorAction SilentlyContinue } | Where-Object {!$_.PSIsContainer -and $_.Length -lt 100000 } | Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match "power" } | Select-Object -ExpandProperty FullName

#>

#UpdateModule

#PublishModule2
#$x=1


