#Requires -RunAsAdministrator
# DoubtfulTurnip's Microsoft Logs Exporter and Analyser
#
# @author:    DoubfulTurnip
# @copyright: Copyright (c) 2024 DoubfulTurnip. All rights reserved.
# @url:       https://github.com/DoubtfulTurnip/AIOMSLogs/
# @date:      2024-09-25
#
#
#
#
# Dependencies:
#
# Microsoft Extractor Suite 
# https://github.com/invictus-ir/Microsoft-Extractor-Suite
#
# Microsoft-Analyzer-Suite (Community Edition)
# https://github.com/evild3ad/Microsoft-Analyzer-Suite
#
# Git for Windows
# https://git-scm.com/downloads/win
#
# Optional:
#
# SANS Sof-Elk
# https://www.sans.org/tools/sof-elk/
#
# Changelog:
# Version 0.1
# Release Date: 2024-09-25
# Initial Release
#
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Microsoft Logs Exporter and Analyser 

.DESCRIPTION
  MSLOGS.ps1 is a PowerShell script utilized to simplify the extraction and analysis of various Microsoft logs using the Invictus Microsoft Extractor Suite and the Microsoft Analyzer Suite with additional functionality to import logs into a SOF-Elk instance.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite

  https://github.com/evild3ad/Microsoft-Analyzer-Suite
  
  https://www.sans.org/tools/sof-elk/


.EXAMPLE
  PS> .\MSLOGS.ps1

.NOTES
  Author - Doubtfulturnip

.LINK
  https://github.com/DoubtfulTurnip/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

$banner = @"                                                                                    

                                                                                                                                                                                                      
                                                                                                                                                                                                                                
"@
$key = 0..255 | Get-Random -Count 32 | %{[byte]$_} 
####
#### Begin Install Modules
####
function Install-RequiredPSModules {
	Write-Host ""
	Write-Host ""
	Read-Host "Ensure Git for Windows has been installed prior to installation. Press any key to continue with the installation or CTRL+C to quit"

	#Install PS Modules
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing Microsoft Extractor Suite..." -ForegroundColor Green
	if( (Get-Module Microsoft-Extractor-Suite -ListAvailable)){
		Write-Host "MES Already Installed, continuing..."
		}
	if(-not (Get-Module Microsoft-Extractor-Suite -ListAvailable)){
	Install-Module Microsoft-Extractor-Suite -Force -AllowClobber
	}
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing Microsoft Graph..." -ForegroundColor Green
	if( (Get-Module Microsoft.Graph -ListAvailable)){
		Write-Host "Microsoft Graph Already Installed, continuing..."
		}
	if(-not (Get-Module Microsoft.Graph -ListAvailable)){
	Install-Module Microsoft.Graph -Force -AllowClobber
	Install-Module Microsoft.Graph.Beta -Force -AllowClobber
	}
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing ExchangeOnlineManagement..." -ForegroundColor Green
	if( (Get-Module ExchangeOnlineManagement -ListAvailable)){
		Write-Host "ExchangeOnlineManagement Already Installed, continuing..."
		}
	if(-not (Get-Module ExchangeOnlineManagement -ListAvailable)){
	Install-Module Microsoft.Graph -Force -AllowClobber
	}
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing Az..." -ForegroundColor Green
	if( (Get-Module Az.* -ListAvailable)){
		Write-Host "Az Already Installed, continuing..."
		}
	if(-not (Get-Module Az.* -ListAvailable)){
	Install-Module Az -Force -AllowClobber
	}
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing AzureADPreview..." -ForegroundColor Green
	if( (Get-Module AzureADPreview -ListAvailable)){
		Write-Host "AzureADPreview Already Installed, continuing..."
		}
	if(-not (Get-Module AzureADPreview -ListAvailable)){
	Install-Module AzureADPreview -Force -AllowClobber
	}
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Installing ImportExcel..." -ForegroundColor Green
	if( (Get-Module ImportExcel -ListAvailable)){
		Write-Host "ImportExcel Already Installed, continuing..."
		}
	if(-not (Get-Module ImportExcel -ListAvailable)){
	Install-Module ImportExcel -Force -AllowClobber
	}

	
	#Install Microsoft Analyzer Suite
    $checkgitlocation = 'C:\Program Files\Git'
    Write-Host ""
    Write-Host ""
    Write-Host "Checking to see if Git is installed..." -ForegroundColor Green
    Write-Host ""
    Write-Host ""
    if (Test-Path -Path $checkgitlocation) {
    Write-Host ""
    Write-Host ""
    Write-Host "Git installed, continuing..." -ForegroundColor Green
    Write-Host ""
    Write-Host ""
    Write-Host "Installing Microsoft Analyzer Suite..." -ForegroundColor Green
	#Check if MAS is already installed, otherwise continue with installation
    Write-Host ""
		if (Test-Path -Path $env:USERPROFILE\Documents\PSScripts\MAS\) {
			Write-Host "Microsoft Analyzer Suite already installed" -Foreground Green
			Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
		}
		else {	
				#Create MAS Folder	
    			New-Item -ItemType "directory" -Path "$env:USERPROFILE\Documents\PSScripts\MAS\" -Force | Out-Null
				#Clone MAS to folder
    			Invoke-Expression "git clone https://github.com/evild3ad/Microsoft-Analyzer-Suite.git $env:USERPROFILE\Documents\PSScripts\MAS\"
    			Write-Host ""
				Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"
				#Set MAS script locations
				$ualanalyzerlocation = "$env:USERPROFILE\Documents\PSScripts\MAS\UAL-Analyzer.ps1"
				$ADsigninlogsanalyzerlocation = "$env:USERPROFILE\Documents\PSScripts\MAS\ADSignInLogsGraph-Analyzer.ps1"
				$MTLAnalyzerLocation = "$env:USERPROFILE\Documents\PSScripts\MAS\MTL-Analyzer.ps1"

				$ipinfotoken = Read-Host -AsSecureString -Prompt "Enter IPInfo Token" 
				$ipinfotokensecure = $ipinfotoken | ConvertFrom-SecureString -key $key 
				Set-Content -Path $ipinfofilesetget -Value $ipinfotokensecure
				$encStr = Get-Content $ipinfofilesetget
				$ipinfotoken = $encStr | ConvertTo-SecureString -Key $key 
				$ipinfotoken = [System.Net.NetworkCredential]::new("", $ipinfotoken).Password

				#Replace access_token line in scripts that use it with actual token
				$string = Get-Content $ualanalyzerlocation
				$string[207] = $string[207] -replace("access_token", "$ipinfotoken")
				$string | Set-Content -Path $ualanalyzerlocation

				$string = Get-Content $ADsigninlogsanalyzerlocation
				$string[126] = $string[126] -replace("access_token", "$ipinfotoken")
				$string | Set-Content -Path $ADsigninlogsanalyzerlocation

				$string = Get-Content $MTLAnalyzerLocation
				$string[148] = $string[148] -replace("access_token", "$ipinfotoken")
				$string | Set-Content -Path $MTLAnalyzerLocation

				Write-Host "Installation Complete!" -ForegroundColor Green
    			Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
			}
		}
	else {
	#If Git for Windows is not installed end with error
    Write-Host "Git not installed, unable to continue with installation" -ForegroundColor Red
    Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
	    }
		

	}


####
#### Begin Update Modules
####
function Update-RequiredModules {

	#Update Script
	#Change directory to the analyzer suite
	Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS"
	#Set locations as variables
    $maslocation = "$env:USERPROFILE\Documents\PSScripts\MAS"
	$UALanalyzerlocation = "$maslocation\UAL-Analyzer.ps1"
	$ADsigninlogsanalyzerlocation = "$maslocation\ADSignInLogsGraph-Analyzer.ps1"
	$MTLAnalyzerLocation = "$maslocation\MTL-Analyzer.ps1"
	
	#Get content of IPinfotoken and store as variable
	$ipinfofile = Test-Path -Path "$env:USERPROFILE\Documents\PSScripts\IPinfotoken.encrypted"
	$ipinfofilesetget = "$env:USERPROFILE\Documents\PSScripts\IPinfotoken.encrypted"
	if ($ipinfofile) {
		$encStr = Get-Content $ipinfofilesetget
		$ipinfotoken = $encStr | ConvertTo-SecureString -Key $key 
        $ipinfotoken = [System.Net.NetworkCredential]::new("", $ipinfotoken).Password
		} else {
		Write-Host "IP Info Token Missing"
		$ipinfotoken = Read-Host -AsSecureString -Prompt "Enter IPInfo Token" 
		$ipinfotokensecure = $ipinfotoken | ConvertFrom-SecureString -key $key 
		Set-Content -Path $ipinfofilesetget -Value $ipinfotokensecure
		$encStr = Get-Content $ipinfofilesetget
		$ipinfotoken = $encStr | ConvertTo-SecureString -Key $key 
        $ipinfotoken = [System.Net.NetworkCredential]::new("", $ipinfotoken).Password
		}
	







	#Re-clone the repo after resetting
	git reset --hard HEAD
	git pull
	Pop-Location
	#Replace access_token line in scripts that use it with actual token
	$string = Get-Content $UALanalyzerlocation
	$string[207] = $string[207] -replace("access_token", "$ipinfotoken")
	$string | Set-Content -Path $UALanalyzerlocation

	$string = Get-Content $ADsigninlogsanalyzerlocation
	$string[126] = $string[126] -replace("access_token", "$ipinfotoken")
	$string | Set-Content -Path $ADsigninlogsanalyzerlocation

	$string = Get-Content $MTLAnalyzerLocation
	$string[148] = $string[148] -replace("access_token", "$ipinfotoken")
	$string | Set-Content -Path $MTLAnalyzerLocation

	Write-Host "Update Complete!" -ForegroundColor Green
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	
	}


####
#### Begin Graph Permissions
####
function Get-MSGraphPermissions {

	Write-Host "This will send a request to the admin of the tenancy to allow MS Graph to function." -ForegroundColor Green 
	Write-Host "" 
	Start-Sleep 2
	Write-Host "Scripts requiring MS Graph API access are labelled with (G) in the main menu"
	Write-Host ""
	Read-Host -Prompt "Press any key to continue with the request or CTRL+C to quit" | Out-Null 
	Connect-MgGraph -Scopes 'User.Read.All,UserAuthenticationMethod.Read.All,AuditLog.Read.All,IdentityRiskEvent.Read.All,IdentityRiskyUser.Read.All' -ErrorAction SilentlyContinue
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 

}


####
#### Begin Selection Functions
####


####
#### 1
####
function Get-UAL-ALL {

	Write-Host "This script will automatically download and analyse all UAL log data over the last 90 days" -ForegroundColor Green
	Write-Host "You will be asked to provide details for the SOF-Elk instance" -ForegroundColor Green
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\" | Out-Null

	#Connect to M365 with tenancy creds
	Connect-m365

	#Export UAL log files for specified user and merge into one file
	Get-UALALL -OutputDir $env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\ -Output JSON

	#Configure variables for transfer
	$userID = "elk_user"
	$localPath = "$env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\*"

	#Enter SOF-Elk IP Address
	$elkIP = Read-Host "Enter SOF-Elk IP"

	#Transfer files to SOF-Elk for ingestion
	$cmd = "scp -r $localpath $UserID@${elkIP}:/logstash/microsoft365/" 

	Invoke-Expression $cmd

	Write-Host ""
	Write-Host ""
	Write-Host "The logs are now being ingested by SOF-Elk"
	Write-Host "The SOF-Elk instance can be access by browsing to http://${elkip}:5601/"
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
}

####
#### 2
####
function Get-MSMFA {

	Write-Host "This script will automatically download and analyse MFA data for an organisation" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Import-Module Microsoft.Graph.Authentication
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MFA\" | Out-Null
	

	#Export Mailbox Items Accessed log files for specified user
	Get-MFA -OutputDir "$env:USERPROFILE\Desktop\$projectname\MFA"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#MFA-Analyzer does not have -Path support
	Write-Host "You will need to select the YYYYMMDDTTTT-MFA-AuthenticationMethods.csv file to use with MFA-Analyser" -ForegroundColor Red
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\MFA" -ForegroundColor Red
	Start-Sleep 5
	Write-Host ""
	Write-Host ""
	#Run analyzer on the export
	& .\MFA-Analyzer.ps1 
	Pop-Location
	Move-Item -Path $env:USERPROFILE\Desktop\MFA-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\MFA\Analysis\ -ErrorAction SilentlyContinue
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

####
#### 3
####
function Get-MSRiskyUsers {

	Write-Host "This script will automatically download and analyse RiskyUser for an organisation" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Import-Module Microsoft.Graph.Authentication
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\RiskyUsers\" | Out-Null
	
	#Export Mailbox Items Accessed log files for specified user
	Get-RiskyUsers -OutputDir "$env:USERPROFILE\Desktop\$projectname\RiskyUsers"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#RiskyUsers-Analyzer does not have -Path support
	Write-Host ""
	Write-Host ""
	Write-Host "You will need to select the RiskyUsers.csv file to use with RiskyUsers-Analyser" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\RiskyUsers\" -ForegroundColor Red
	Write-Host ""
	Write-Host "If the output directory is empty, no risky users were found" -ForegroundColor Red
	Start-Sleep 5
	Write-Host ""
	Write-Host ""

	#Run analyzer on the export
	& .\RiskyUsers-Analyzer.ps1 -ErrorAction SilentlyContinue
	Pop-Location
	Move-Item -Path $env:USERPROFILE\Desktop\RiskyUsers-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\RiskyUsers\Analysis\ -ErrorAction SilentlyContinue
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

####
#### 4
####
function Get-MSUsers {

	Write-Host "This script will automatically download and analyse Users within an organisation" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Import-Module Microsoft.Graph.Authentication
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\Users\" | Out-Null

	#Export Users
	Get-Users -OutputDir "$env:USERPROFILE\Desktop\$projectname\Users"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Users-Analyzer does not have -Path support
	Write-Host ""
	Write-Host ""
	Write-Host "You will need to select the YYYYMMDDTTTT-Users.csv file to use with Users-Analyser" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\Users\" -ForegroundColor Red
	Write-Host ""
	Start-Sleep 5
	Write-Host ""
	Write-Host ""
	
	#Run analyzer on the export
	& .\Users-Analyzer.ps1 -ErrorAction SilentlyContinue
	Pop-Location
	Move-Item -Path $env:USERPROFILE\Desktop\Users-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\Users\Analysis\ -ErrorAction SilentlyContinue
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

####
#### 5
####
function Get-MS-Oauth {

	Write-Host "This script will automatically download Oauth data for an entire organisation" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\Oauth\" | Out-Null
	
	#Connect to AzureAD with tenancy creds
	Connect-AzureAD
	
	#Export Mailbox rules log files for specified user
	Get-OAuthPermissions -OutputDir "$env:USERPROFILE\Desktop\$projectname\Oauth\"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the exported merge
	& .\OAuthPermissions-Analyzer.ps1 -ErrorAction SilentlyContinue
	Pop-Location
	Move-Item -Path $env:USERPROFILE\Desktop\OAuthPermissions-Analyzer -Destination $env:USERPROFILE\Desktop\$projectname\Oauth\
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}



####
#### 7
####
function Get-MSRiskyDetections {

	Write-Host "This script will automatically download and analyse Risky Detections" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Import-Module Microsoft.Graph.Authentication
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\RiskyDetections\" | Out-Null
	
	#Export RiskyDetections log files for specified user
	Get-RiskyDetections -OutputDir "$env:USERPROFILE\Desktop\$projectname\RiskyDetections\"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#RiskyDetections-Analyzer does not have -Path support
	Write-Host "If there are no Risky Detections the folder will be empty, in this case just cancel the selection" -ForegroundColor Red
	Write-Host ""
	Write-Host ""
	Write-Host "You will need to select the RiskyDetections.csv file to use with RiskyDetections-Analyzer" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\RiskyDetections\" -ForegroundColor Red
	Write-Host ""
	Start-Sleep 5
	Write-Host ""
	Write-Host ""

	#Run analyzer on the export
	& .\RiskyDetections-Analyzer.ps1 -ErrorAction SilentlyContinue
	Pop-Location
	Move-Item -Path $env:USERPROFILE\Desktop\RiskyDetections-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\RiskyDetections\Analysis\ -ErrorAction SilentlyContinue
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

####
#### 8
####
function Get-MS-MailboxRulesOrg {

	Write-Host "This script will automatically download Exchange mailbox rules for an entire organisation" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MailboxRules\Org\" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox rules log files for specified user
	Get-MailboxRules -OutputDir $env:USERPROFILE\Desktop\$projectname\MailboxRules\Org\

	Write-Host "If the folder is empty then no rules were discovered" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 

}

####
#### 9
####
function Get-UAL-User {

	Write-Host "This script will automatically download and analyse UAL log data for a specified user over the last 90 days" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"

	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\UAL\CSV\$useraccount" | Out-Null

	#Connect to M365 with tenancy creds	
	Connect-m365

	#Export UAL log files for specified user and merge into one file
	Get-UALALL -OutputDir $env:USERPROFILE\Desktop\$projectname\UAL\CSV\$useraccount\ -MergeOutput -UserIds $useraccount

	#Change directory to the analyzer suite
	Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the exported merge
	& .\UAL-Analyzer.ps1 -Path $env:USERPROFILE\Desktop\$projectname\UAL\CSV\$useraccount\Merged\UAL-Combined.csv -OutputDir $env:USERPROFILE\Desktop\$projectname\UAL\CSV\$useraccount\analysis\
	Pop-Location
    Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
}

####
#### 10
####
function Get-MS-MailboxItemsAccessed {

	Write-Host "This script will automatically download Exchange MailItemsAccessed data for a specified user" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	Write-Host ""
	$startdate = Read-Host "Provide the start date (Format: D/M/YYYY)"
	Write-Host ""
	$enddate = Read-Host "Provide the end date (Format: D/M/YYYY)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MailItemsAccessed\$useraccount" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox Items Accessed log files for specified user
	Get-Sessions -StartDate $startdate -EndDate $enddate -UserIds $useraccount -OutputDir "$env:USERPROFILE\Desktop\$projectname\MailItemsAccessed\$useraccount\"
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

####
#### 11
####
function Get-MS-MailboxRulesUser {

	Write-Host "This script will automatically download Exchange mailbox rules for a specified user" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MailboxRules\$useraccount" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox rules log files for specified user
	Get-MailboxRules -OutputDir $env:USERPROFILE\Desktop\$projectname\MailboxRules\$useraccount\ -UserIds $useraccount

	Write-Host "If the folder is empty then no rules were discovered" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	
}

####
#### 6
####
function Get-MS-MTL {

	Write-Host "This script will automatically download Message Trace Logs for a specified user" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MTL\" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-M365
	
	#Export MTL log files for specified user
	Get-MessageTraceLog -OutputDir "$env:USERPROFILE\Desktop\$projectname\MTL\"  -UserIds $useraccount

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the export
	& .\MTL-Analyzer.ps1 -OutputDir $env:USERPROFILE\Desktop\$projectname\MTL\Analysis\ -Path $env:USERPROFILE\Desktop\$projectname\MTL\$useraccount-MTL.csv -ErrorAction SilentlyContinue
	Pop-Location
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 
}

function Get-MS-AllTheThings {

	Write-Host "This script will automatically download all data and analyse where possible" -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Import-Module Microsoft.Graph.Authentication
	$projectname = Read-Host "Provide a projectname for folder structure creation (e.g. DDMMYYYY)"

	Start-Sleep 2
	Write-Host ""
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MFA\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\RiskyUsers\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\Users\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\Oauth\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\RiskyDetections\" | Out-Null
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$projectname\MailboxRules\Org\" | Out-Null


	##Exports
	#Connect to M365 with tenancy creds
	Connect-m365
	#Export UAL log files for specified user and merge into one file
	Get-UALALL -OutputDir $env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\ -Output JSON
	#Export Mailbox Items Accessed log files for specified user
	Get-RiskyUsers -OutputDir "$env:USERPROFILE\Desktop\$projectname\RiskyUsers"
	#Export MFA Logs
	Get-MFA -OutputDir "$env:USERPROFILE\Desktop\$projectname\MFA"
	#Export RiskyDetections Logs
	Get-RiskyDetections -OutputDir "$env:USERPROFILE\Desktop\$projectname\RiskyDetections\"
	#Export Mailbox Rules
	Get-MailboxRules -OutputDir $env:USERPROFILE\Desktop\$projectname\MailboxRules\Org\
	#Export Users
	Get-Users -OutputDir "$env:USERPROFILE\Desktop\$projectname\Users"

	Connect-AzureAD
	#Export OAuth Logs
	Get-OAuthPermissions -OutputDir "$env:USERPROFILE\Desktop\$projectname\Oauth\"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"
	Start-Sleep 5
	Write-Host ""
	Write-Host ""


	#Run analyzers on the export
	Write-Host "If any directories are empty during selection it means that there was no data found to export. Click cancel on the file selection window to continue to the next analyser..."
	Write-Host ""
	Write-Host "Starting MFA Analysis..."
	Write-Host ""
	Write-Host "You will need to select the YYYYMMDDTTTT-MFA-AuthenticationMethods.csv file to use with MFA-Analyser" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\MFA" -ForegroundColor Red
	Write-Host ""
	& .\MFA-Analyzer.ps1 
	Write-Host ""
	Write-Host "Starting RiskyUsers Analysis..." -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Write-Host "You will need to select the RiskyUsers.csv file to use with RiskyUsers-Analyser" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\RiskyUsers\" -ForegroundColor Red
	& .\RiskyUsers-Analyzer.ps1 -ErrorAction SilentlyContinue
	Write-Host ""
	Write-Host "Starting Users Analysis..." -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Write-Host "You will need to select the YYYYMMDDTTTT-Users.csv file to use with Users-Analyser" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\Users\" -ForegroundColor Red
	Write-Host ""
	& .\Users-Analyzer.ps1 -ErrorAction SilentlyContinue
	Write-Host ""
	Write-Host "Starting Oauth Analysis..." -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Write-Host "You will need to select the YYYYMMDDTTTT-OAuthPermissions.csv file to use with OAuthPermissions-Analyzer" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\Oauth\" -ForegroundColor Red
	Write-Host ""
	& .\OAuthPermissions-Analyzer.ps1 -ErrorAction SilentlyContinue
	Write-Host ""
	Write-Host "Starting Risky Detections Analysis..." -ForegroundColor DarkGreen -BackgroundColor DarkRed
	Write-Host ""
	Write-Host "You will need to select the RiskyDetections.csv file to use with RiskyDetections-Analyzer" -ForegroundColor Red
	Write-Host ""
	Write-Host "It will be located in the following directory $env:USERPROFILE\Desktop\$projectname\RiskyDetections\" -ForegroundColor Red
	Write-Host ""
	& .\RiskyDetections-Analyzer.ps1 -ErrorAction SilentlyContinue

	Pop-Location

	#Move Analysis Temp Folders
	Move-Item -Path $env:USERPROFILE\Desktop\MFA-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\MFA\Analysis\ -ErrorAction SilentlyContinue
	Move-Item -Path $env:USERPROFILE\Desktop\RiskyUsers-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\RiskyUsers\Analysis\ -ErrorAction SilentlyContinue
	Move-Item -Path $env:USERPROFILE\Desktop\Users-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\Users\Analysis\ -ErrorAction SilentlyContinue
	Move-Item -Path $env:USERPROFILE\Desktop\OAuthPermissions-Analyzer -Destination $env:USERPROFILE\Desktop\$projectname\Oauth\Analysis\ -ErrorAction SilentlyContinue
	Move-Item -Path $env:USERPROFILE\Desktop\RiskyDetections-Analyzer\ -Destination $env:USERPROFILE\Desktop\$projectname\RiskyDetections\Analysis\ -ErrorAction SilentlyContinue

	#SOF-ELK Transfer
	#Configure variables for transfer
	$userID = "elk_user"
	$localPath = "$env:USERPROFILE\Desktop\$projectname\All-UAL\JSON\*"
	#Enter SOF-Elk IP Address
	$elkIP = Read-Host "Enter SOF-Elk IP"
	#Transfer files to SOF-Elk for ingestion
	$cmd = "scp -r $localpath $UserID@${elkIP}:/logstash/microsoft365/" 
	Invoke-Expression $cmd

	#Finish with info
	Write-Host ""
	Write-Host "The logs are now being ingested by SOF-Elk"
	Write-Host "The SOF-Elk instance can be access by browsing to http://${elkip}:5601/"
	Write-Host ""
	Write-Host "All available logs and analysis are located in the directory $env:USERPROFILE\Desktop\$projectname\"
	Write-Host ""
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
}



#### Main Menu ####

function Show-MainMenu {

	param (
		[string]$Title = "Microsoft Log Exporter and Analyser"
	)
cls
	$banner
	Write-Host "============ $Title ===========" -ForegroundColor Red
	Write-Host "(G) = Requires MS Graph API Access" -ForegroundColor DarkGreen
	Write-Host "(A) = Uses Microsoft Analyzer Suite" -ForegroundColor DarkGreen
	Write-Host "(S) = Uses Sof-Elk Instance" -ForegroundColor DarkGreen

 	Write-Host "============ Organisation Export ===========" -ForegroundColor Red
	Write-Host "1: Press '1' To download and analyse UAL logs (S)" -ForegroundColor DarkMagenta
	Write-Host "2: Press '2' To download and analyse MFA Logs (G)(A)" -ForegroundColor DarkMagenta
	Write-Host "3: Press '3' To download and analyse RiskyUsers (G)(A)" -ForegroundColor DarkMagenta
	Write-Host "4: Press '4' To download and analyse User Accounts (G)(A)" -ForegroundColor DarkMagenta
	Write-Host "5: Press '5' To download and analyse Oauth data (A)" -ForegroundColor DarkMagenta
	Write-Host "6: Press '6' To download and analyse Risky Detections (A)(G)" -ForegroundColor DarkMagenta
	Write-Host "7: Press '7' To download email rules" -ForegroundColor DarkMagenta


	Write-Host "============ Specific User Export ===========" -ForegroundColor Red
	Write-Host "8: Press '8' To download and analyse UAL logs (A)"  -ForegroundColor DarkYellow
	Write-Host "9: Press '9' To download Mail Accessed Items" -ForegroundColor DarkYellow
	Write-Host "10: Press '10' To download email rules" -ForegroundColor DarkYellow
	Write-Host "11: Press '11' To download and analyse Message Trace Log data (A)" -ForegroundColor DarkYellow
 
	Write-Host "============ Hail Mary ===========" -ForegroundColor Red
	Write-Host "12: Press '12' To download and analyse ALL LOGS (ORG)-(A)(G)(S)"  -ForegroundColor DarkBlue

	Write-Host "============================================" -ForegroundColor Red
	Write-Host "I: Press 'I' Install PowerShell Modules" -ForegroundColor DarkCyan
	Write-Host "U: Press 'U' Update PowerShell Modules" -ForegroundColor DarkCyan
	Write-Host "G: Press 'G' Send request for MS Graph API access" -ForegroundColor DarkCyan
	Write-Host "Q: Press 'Q' to quit" -Foregroundcolor Red -Backgroundcolor White
			}

do 
			{
		Show-MainMenu
		$selection = Read-Host "Please make a selection"
		switch ($selection)
		{

#To download and analyse UAL logs
		'1' {
		Get-UAL-ALL
			}
#To download and analyse MFA Logs
		'2' {
		Get-MSMFA
			}
#To download and analyse RiskyUsers
		'3' {
		Get-MSRiskyUsers
			}
#To download and analyse User Accounts
		'4' {
		Get-MSUsers
			}	
#To download and analyse Oauth data
		'5' {
		Get-MS-Oauth
			}
#To download and analyse Message Transport Rules
		'6' {
		Get-MSRiskyDetections
			}		
#To download email rules
 		'7' {
		Get-MS-MailboxRulesOrg
			}
#To download and analyse UAL logs
		'8' {
		Get-UAL-User
			}
#To download Mail Accessed Items
		'9' {
		Get-MS-MailboxItemsAccessed
			}
#To download email rules
		'10' {
		Get-MS-MailboxRulesUser
			}	
#To download and analyse Message Trace Log data
		'11' {
		Get-MS-MTL
			}
#To download all the things (org)
		'12'{
		Get-MS-AllTheThings
			}


				
###		
		'I' {
		Install-RequiredPSModules
			}
		'U' {
		Update-RequiredModules
			}
		'G' {
		Get-MSGraphPermissions
			}
		
			

		}
			}
until ($selection -eq 'q')


Show-MainMenu
