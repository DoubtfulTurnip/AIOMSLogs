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
				#Enter IPinfo.io token to be saved as a file and later used as a variable (bad secret practice, I know, will fix later)
				Read-Host "Enter IP Info Token" | Out-File -FilePath $env:USERPROFILE\Documents\PSScripts\IPinfotoken.txt
				#Get content of IPinfotoken and store as variable
				$ipinfotoken = Get-Content $env:USERPROFILE\Documents\PSScripts\IPinfotoken.txt
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
	$ipinfotoken = Get-Content $env:USERPROFILE\Documents\PSScripts\IPinfotoken.txt
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

function Get-UAL-User {

	Write-Host "This script will automatically download and analyse UAL log data for a specified user over the last 90 days" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"

	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\UAL\CSV\$useraccount" | Out-Null

	#Connect to M365 with tenancy creds	
	Connect-m365

	#Export UAL log files for specified user and merge into one file
	Get-UALALL -OutputDir $env:USERPROFILE\Desktop\$name\UAL\CSV\$useraccount\ -MergeOutput -UserIds $useraccount

	#Change directory to the analyzer suite
	Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the exported merge
	& .\UAL-Analyzer.ps1 -Path $env:USERPROFILE\Desktop\$name\UAL\CSV\$useraccount\Merged\UAL-Combined.csv -OutputDir $env:USERPROFILE\Desktop\$name\UAL\CSV\$useraccount\analysis\
	Pop-Location

	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 
}



function Get-UAL-ALL {

	Write-Host "This script will automatically download and analyse all UAL log data over the last 90 days" -ForegroundColor Green
	Write-Host "You will be asked to provide details for the SOF-Elk instance" -ForegroundColor Green
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\All-UAL\JSON\" | Out-Null

	#Connect to M365 with tenancy creds
	Connect-m365

	#Export UAL log files for specified user and merge into one file
	Get-UALALL -OutputDir $env:USERPROFILE\Desktop\$name\All-UAL\JSON\ -Output JSON

	#Configure variables for transfer
	$userID = "elk_user"
	$localPath = "$env:USERPROFILE\Desktop\$name\All-UAL\JSON\*"

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


function Get-MS-MailboxRulesUser {

	Write-Host "This script will automatically download Exchange mailbox rules for a specified user" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\MailboxRules\$useraccount" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox rules log files for specified user
	Get-MailboxRules -OutputDir $env:USERPROFILE\Desktop\$name\MailboxRules\$useraccount\ -UserIds $useraccount

	Write-Host "If the folder is empty then no rules were discovered" -ForegroundColor Green -BackgroundColor Red
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	

}


function Get-MS-MailboxRulesOrg {

	Write-Host "This script will automatically download Exchange mailbox rules for an entire organisation" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\MailboxRules\Org\" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox rules log files for specified user
	Get-MailboxRules -OutputDir $env:USERPROFILE\Desktop\$name\MailboxRules\Org\

	Write-Host "If the folder is empty then no rules were discovered" -ForegroundColor Green -BackgroundColor Red
	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 

}


function Get-MS-Oauth {

	Write-Host "This script will automatically download Oauth data for an entire organisation" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""

	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\Oauth\" | Out-Null
	
	#Connect to AzureAD with tenancy creds
	Connect-AzureAD
	
	#Export Mailbox rules log files for specified user
	Get-OAuthPermissions -OutputDir "$env:USERPROFILE\Desktop\$name\Oauth\"

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the exported merge
	& .\OAuthPermissions-Analyzer.ps1 -ErrorAction SilentlyContinue
	Pop-Location

	Move-Item -Path $env:USERPROFILE\Desktop\OAuthPermissions-Analyzer -Destination $env:USERPROFILE\Desktop\$name\Oauth\

	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 

}


function Get-MS-MTL {

	Write-Host "This script will automatically download Message Trace Logs for a specified user" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\MTL\" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-M365
	
	#Export MTL log files for specified user
	Get-MessageTraceLog -OutputDir "$env:USERPROFILE\Desktop\$name\MTL\"  -UserIds $useraccount

	#Change directory to the analyzer suite
    Push-Location "$env:USERPROFILE\Documents\PSScripts\MAS\"

	#Run analyzer on the export
	& .\MTL-Analyzer.ps1 -OutputDir $env:USERPROFILE\Desktop\$name\MTL\Analysis\ -Path $env:USERPROFILE\Desktop\$name\MTL\$useraccount-MTL.csv -ErrorAction SilentlyContinue
	Pop-Location

	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 

}




function Get-MS-MailboxItemsAccessed {

	Write-Host "This script will automatically download Exchange MailItemsAccessed data for a specified user" -ForegroundColor Green -BackgroundColor Red
	Start-Sleep 3
	Write-Host ""
	Write-Host ""
	$name = Read-Host "Provide a name for folder structure creation (e.g. DDMMYYYY)"
	Write-Host ""
	$useraccount = Read-Host "Provide the user account name (e.g. first.surname@company.com)"
	Write-Host ""
	$startdate = Read-Host "Provide the start date (Format: D/M/YYYY)"
	Write-Host ""
	$enddate = Read-Host "Provide the end date (Format: D/M/YYYY)"
	
	#Create new folder
	New-Item -ItemType "directory" -Path "$env:USERPROFILE\Desktop\$name\MailItemsAccessed\$useraccount" | Out-Null
	
	#Connect to M365 with tenancy creds
	Connect-m365
	
	#Export Mailbox Items Accessed log files for specified user
	Get-Sessions -StartDate $startdate -EndDate $enddate -UserIds $useraccount -OutputDir "$env:USERPROFILE\Desktop\$name\MailItemsAccessed\$useraccount\"



	Read-Host -Prompt "Press any key to return to the Main Menu or CTRL+C to quit" | Out-Null 	 

}









function Show-MainMenu {

	param (
		[string]$Title = "Microsoft Log Exporter and Analyser"
	)
cls
	Write-Host ""
	$banner
	Write-Host ""
	Write-Host "============ $Title ===========" -ForegroundColor Red
	Write-Host ""
	Write-Host "1: Press '1' To download and analyse UAL logs for a specified user using the Microsoft Analyser Suite"  -ForegroundColor DarkMagenta
	Write-Host "2: Press '2' To download and analyse all UAL logs within SOF-ELK" -ForegroundColor DarkMagenta
	Write-Host "3: Press '3' To download email rules for a specified user" -ForegroundColor DarkMagenta
	Write-Host "4: Press '4' To download email rules for an entire organisation" -ForegroundColor DarkMagenta
	Write-Host "5: Press '5' To download and analyse MS Oauth data using the Microsoft Analyser Suite" -ForegroundColor DarkMagenta
	Write-Host "6: Press '6' To download and analyse MS Message Trace Log data using the Microsoft Analyser Suite" -ForegroundColor DarkMagenta
	Write-Host "7: Press '7' To download MS Mail Accessed Items for a specified user" -ForegroundColor DarkMagenta
	Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
	Write-Host ""
	Write-Host "I: Press 'I' Install PowerShell Modules" -ForegroundColor DarkCyan
	Write-Host "U: Press 'U' Update PowerShell Modules" -ForegroundColor DarkCyan
	Write-Host ""
	Write-Host "Q: Press 'Q' to quit" -Foregroundcolor Red -Backgroundcolor White
	Write-Host ""
			}

do 
			{
		Show-MainMenu
		$selection = Read-Host "Please make a selection"
		switch ($selection)
		{
		
		'1' {
		Get-UAL-User
			}
		'2' {
		Get-UAL-ALL
			}
		'3' {
		Get-MS-MailboxRulesUser
			}		
		'4' {
		Get-MS-MailboxRulesOrg
			}
		'5' {
		Get-MS-Oauth
			}
		'6' {
		Get-MS-MTL
			}
		'7' {
		Get-MS-MailboxItemsAccessed
			}
		'I' {
		Install-RequiredPSModules
			}
		'U' {
		Update-RequiredModules
			}


		}
			}
until ($selection -eq 'q')


Show-MainMenu
