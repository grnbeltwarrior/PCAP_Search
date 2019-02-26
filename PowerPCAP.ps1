<# Powershell script to use tshark.exe to do work with pcaps.
Twiiter: @grnbeltwarrior
Last updated: 2019/02/26
Feed the script the path to the pcap files, it will get a list of the pcap files and iterate through them.
OR
Feed the script a pcap file with -singlePCAP

Import-Module PowerPCAP.ps1

Use: PS H:\> Invoke-PowerPCAP.ps1 Z:\Directory\Path\To\PCAPS\

TODO:
If the path passed doesn't have \ at the end, it will barf. I'll get to it sometime.
Implement the functions for grepping the TCP streams for each of the found credit card numbers in the pcap.
These are designed but not included in this script.
#>

Function Invoke-PowerPCAP 
{

[CmdletBinding()]
param (
    [string]$pcapDirectory = $(throw "-pcapDirectory is required."),
    [switch]$singlePCAP = $false,
    [switch]$smb = $false,
    [switch]$http = $false,
    [switch]$ccsrch = $false,
    [switch]$runAll = $false
)

# Determine if the user wants to perform actions on a single pcap or a list in a directory.
$global:cardNumberArray = @()

    if ($singlePCAP -eq $true){
        $pcap = $pcapDirectory.split("\")[-1]
        if ($pcap -like "*PCAP"){
            Write-Host "Starting to dig into: " $pcap
            # split path from pcap
            $pcapPath = Split-Path -Path $pcapDirectory
            $outPath = $pcap.split(".")[0]
            $pcapPath += "\" + $outPath
            buildOutput $pcapPath
            checkProtocols $pcap $pcapPath
            # Main area of work
            if ($runAll -eq $true) {$smb = $true; $http = $true; $ccsrch = $true}
            if ($http -eq $true){
                httpFiles $pcap $pcapPath
            }
            if ($smb -eq $true){
                smbFiles $pcap $pcapPath
            }
            if ($ccsrch -eq $true){Invoke-CCSRCH $pcap $pcapPath}
            Write-Host "Single pcap work completed."
        }
        else {
            # break out and error.
            Write-Host "The file passed is not a pcap file." -ForegroundColor Red
            break
        }
    }

    else {
        # Get's a list of files within the given directory 
        $pcapList = Get-ChildItem $pcapDirectory
        Foreach ($pcap in $pcapList){
            if ($pcap.Name -like "*PCAP"){
                $pcapName = $pcap.Name
                $pcapPath = $pcapDirectory + $pcapName.split(".")[0]
                Write-Host "Starting to dig into: " $pcapName        
                buildOutput $pcapPath
                checkProtocols $pcap $pcapPath
                llmnr_nbns $pcap $pcapPath
                if ($runAll -eq $true) {$smb = $true; $http = $true; $ccsrch = $true}
                if ($http -eq $true){
                    httpFiles $pcap $pcapPath
                }
                if ($smb -eq $true){
                    smbFiles $pcap $pcapPath
                }
                if ($ccsrch -eq $true){Invoke-CCSRCH $pcap $pcapPath}
            }
        }
        Write-Host "Directory pcap work completed."
    }
}

Function buildOutput($pcapPath){
    # Check if dest directory exists, and if not, create it
    if (Test-Path -Path $pcapPath -PathType Container) {
        Write-Host "$pcapPath already exists, proceeding..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Creating $pcapPath and proceeding..." -ForegroundColor Yellow
        New-Item -Path $pcapPath -ItemType directory | Out-Null
    }
}

Function llmnr_nbns($pcap, $pcapPath){
    Write-Host "Looking for LLMNR or NBNS..." -ForegroundColor Magenta
    $outFile = "$pcapPath\LLMNR_NBNS.txt"
    $results = C:\'Program Files'\Wireshark\tshark.exe -r $pcapPath\..\$pcap -Y 'llmnr || nbns' -T fields -e frame.number -e ip.src -e text
    if ($results -ne $null){
        $pcap.Name | Out-File $outFile -Append
        $results | Out-File $outFile -Append
    }
    else {Write-Host "¯\_(ツ)_/¯ LLMNR or NBNS was not found in: " $pcap -ForegroundColor Cyan}
}

Function checkProtocols($pcap, $pcapPath){
    Write-Host "Getting protocols from: " $pcap -ForegroundColor Green
    $outFile = "$pcapPath\Protocol_results.txt"
    $results = C:\'Program Files'\Wireshark\tshark.exe -r $pcapPath\..\$pcap -q -z io,phs,ip
    if ($results -ne $null){
        $pcap.Name | Out-File $outFile -Append
        $results | Out-File $outFile -Append
    }
    else {Write-Host "Something happened, no protocols. Are you sure this is a pcap file?" -ForegroundColor Red}
}

Function smbFiles($pcap, $pcapPath){
    Write-Host "Extracting SMB files from the pcap file..." -ForegroundColor Green
    & C:\'Program Files'\Wireshark\tshark.exe -nr $pcapPath\..\$pcap -q --export-objects smb,$pcapPath\SMBFiles\
    # Then Invoke-PowershellGrep here
    Invoke-PowershellGrep $pcapPath\SMBFiles\
}

Function httpFiles($pcap){
    Write-Host "Extracting HTTP files from the pcap file..." -ForegroundColor Green
    & C:\'Program Files'\Wireshark\tshark.exe -nr $pcapPath\..\$pcap -q --export-objects http,$pcapPath\HTTPFiles\
    # Then Invoke-PowershellGrep here
    Invoke-PowershellGrep $pcapPath\HTTPFiles\
}

Function Invoke-PowershellGrep($pcapPath){
    # The below needs to be changed to accept a variable and then find if either or both SMBFiles or HTTPFiles exist and then grep the files within.
    If (($pcapPath -like '*HTTPFiles*') -OR ($pcapPath -like '*SMBFiles*')){ 
        $ResultsPath = "$pcapPath\PowerShell_Grep_Results\"
        $Today = Get-Date -format yyyyMMdd
        $TargetText= "(username|pass=|password|creditc|userid|appid|loginid|login=|user=|server=|ftp|sftp|ssh|uid|pwd|{xor}|wsadmin)"
        #set up results file path/name
        foreach ($directory in Get-ChildItem $pcapPath) {
            $CleanName = $directory
            $CleanName = "$ResultsPath$CleanName.grepped.$Today.txt"
	        #$Share = $Share.TrimEnd()
	        #$Path = "$Share\*"
            $path = $directory
            $PathArray = @()

            # Check if dest directory exists, and if not, create it
            if (Test-Path -Path $ResultsPath -PathType Container) {
                Write-Host "$ResultsPath already exists, proceeding to needle $Path" -ForegroundColor Yellow
            }
            else {
                Write-Host "Creating $ResultsPath and proceeding to needle $Path" -ForegroundColor Yellow
                New-Item -Path $ResultsPath -ItemType directory | Out-Null
            }
            Write-Host "Getting set to grep files in the following path: " $pcapPath -ForegroundColor Magenta
            # get all the files in $Path that contain the TargetText strings
            Get-ChildItem $Path -Recurse -Include "*.txt","*.log","*.cfg","*.conf","*.config","*.ini","*.cmd","*.bat","*.py","*.properties*","*.sql","*.xml","*password*","*debug*","ssh*","*.ps1"  -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -ne "Directory"} |
                ForEach-Object {
	    	        If (Get-Content $_.FullName | Select-String -Pattern $TargetText) {
		                $Needles = Get-Content $_.FullName | Select-String -Pattern $TargetText
		                $PathArray += $_.FullName 
		                $PathArray += $Needles
		                $PathArray += " "
		                $PathArray += "#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*# "
                        $PathArray += " "
		            }
                }
	        $PathArray | ForEach-Object {$_} |  Out-File $ResultsPath\$CleanName
            Write-Host "Powershell_Grep completed searching through $Path."  -ForegroundColor Yellow
            Write-Host "Please see $ResultsPath\$CleanName for results." -ForegroundColor Yellow
        }
        Write-Host "Powershell_Grep completed needling." -ForegroundColor Yellow
    }
}

<#
    Invoke-CCSRCH
        Runs ccsrch.exe using the passed pcap file.
        Includes a check to see if the number passes the Luhn Algorithm validation.
        If the Luhn Validation passes and the number isn't already in the array, it is added.
        Reduces duplication using the array.
#>
Function Invoke-CCSRCH($pcap){
    Write-Host "Running CCSRCH.exe on: " $pcap -ForegroundColor Green
    $results = C:\'Program Files'\ccsrch-1.0.8-win32\ccsrch.exe $pcapPath\..\$pcap
    if ($results -ne $null){
        foreach ($line in $results){
            # trim to number string (if line ends in n amount of numbers)
            $line = $line.split("`t")[2]
            if ($line -eq $null){
                continue
            }
            else{
                if ($line.toString().length -gt 3){
                    $IsLuhn = Test-LuhnValidation -Number $line
                    if (($global:cardNumberArray -notcontains $line) -AND ($line.length -gt 14) -AND $IsLuhn -eq $true){
                        $global:cardNumberArray += $line
                    }
                }
            }
        }
    }
    Write-Host "All the credit card numbers found: "$global:cardNumberArray -ForegroundColor Yellow
}

<#
    Test-LuhnValidation
        Taken from here: https://www.powershellgallery.com/packages/gibbels-algorithms/1.0.3/Content/scripts%5Cluhn%5CTest-LuhnValidation.ps1
#>
Function Test-LuhnValidation {

    param (
        [Parameter(Mandatory=$True)]
        [string]$Number
    )
    
    $temp = $Number.ToCharArray();
    $numbers = @(0) * $Number.Length;
    $alt = $false;

    for($i = $temp.Length -1; $i -ge 0; $i--) {
       $numbers[$i] = [int]::Parse($temp[$i])
       if($alt){
           $numbers[$i] *= 2
           if($numbers[$i] -gt 9) { 
               $numbers[$i] -= 9 
           }
       }
       $sum += $numbers[$i]
       $alt = !$alt
    }
    return ($sum % 10) -eq 0
}
