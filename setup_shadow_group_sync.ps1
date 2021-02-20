
# set up "shadow groups" -- security groups that are automatically updated by a powershell script triggered by scheduled tasks to keep the membership of the security group matching an OU (or other, flexibly-specified classes of users)
# (based on https://github.com/davegreen/shadowGroupSync)



if (-not (Get-InstalledModule | Where-Object {$_.Name -eq "PasswordsGenerator"})){
    # We require the PasswordsGenerator module (https://gallery.technet.microsoft.com/scriptcenter/Passwords-Generator-Module-222dbff6)
    #One time installation procedure
    # [Net.ServicePointManager]::SecurityProtocol 
    # # # >>>  Ssl3, Tls
    # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Install-Module -Force PasswordsGenerator
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Force PasswordsGenerator
}
Import-Module PasswordsGenerator
Import-Module ActiveDirectory
Import-Module ScheduledTasks



$pathOfShadowGroupSyncScript = Join-Path (Join-Path $env:programfiles "shadowGroupSync") "shadowGroupSync.ps1"
$pathOfShadowGroupSyncConfigurationDirectory = Join-Path $env:programdata "shadowGroupSync"
$pathOfShadowGroupSyncConfigurationFile = Join-Path $pathOfShadowGroupSyncConfigurationDirectory "shadowGroupSyncConfiguration.csv"
$pathOfLogFile = Join-Path $pathOfShadowGroupSyncConfigurationDirectory "shadowGroupSync.log"
$nameOfServiceUser="serviceShadowGroups"
$nameOfScheduledTask = "shadowGroupSync"
$descriptionOfScheduledTask = "updates the shadow groups according to $pathOfShadowGroupSyncConfigurationFile"
# $urlOfShadowGroupSyncScript = "https://raw.githubusercontent.com/davegreen/shadowGroupSync/master/shadowGroupSync.ps1"
$urlOfShadowGroupSyncScript = "https://raw.githubusercontent.com/neiljackson1984/shadowGroupSync/master/shadowGroupSync.ps1"
$nameOfShadowGroupsOrganizationalUnit = "shadow_groups"
$distinguishedNameOfTheRootOrganizationalUnitToBeShadowed="OU=company"  + "," + (Get-ADDomain).DistinguishedName


$passwordOfServiceUser = (New-Password -Pool 1 -CharsLengthArray 5,5,3,3)
#  2020-11-23-1009
#  On some domain controllers, it seems that the maximum allowed password length is 16.  I cannot figure out why this is.
# $passwordOfServiceUser = (New-Password -Pool 1 -CharsLengthArray 5,5)

("passwordOfServiceUser: " + $passwordOfServiceUser) | write-output

mkdir -ErrorAction SilentlyContinue (Split-Path $pathOfShadowGroupSyncScript -Parent)
mkdir -ErrorAction SilentlyContinue $pathOfShadowGroupSyncConfigurationDirectory

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest $urlOfShadowGroupSyncScript -OutFile $pathOfShadowGroupSyncScript


New-ADUser `
    -ErrorAction SilentlyContinue `
    -Path ( "CN=Users" + "," + (Get-ADDomain).DistinguishedName  ) `
    -Name $nameOfServiceUser `
    -AccountPassword (ConvertTo-SecureString $passwordOfServiceUser -AsPlainText -Force  ) `
    -Enabled $True `
    -PassThru 

Add-ADGroupMember -Confirm:$False -Identity "Domain Admins" -Members (Get-ADUser $nameOfServiceUser)
# $serviceUser = Get-ADUser -Filter {Name -eq $nameOfServiceUser} 

$serviceUser = Get-ADUser $nameOfServiceUser
$serviceUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $passwordOfServiceUser -AsPlainText -Force  )    

New-ADOrganizationalUnit -Name $nameOfShadowGroupsOrganizationalUnit -Path (Get-ADDomain).DistinguishedName 
$shadowGroupsOrganizationalUnit = Get-ADOrganizationalUnit ( "OU=" + $nameOfShadowGroupsOrganizationalUnit + "," + (Get-ADDomain).DistinguishedName )
$rootOrganizationalUnitToBeShadowed = Get-ADOrganizationalUnit  $distinguishedNameOfTheRootOrganizationalUnitToBeShadowed
#delete existing configuration file in case it already exists
# Remove-Item -Force $pathOfShadowGroupSyncConfigurationFile

# $rootOrganizationalUnitToBeShadowed 

# $organizationlUnitsToBeShadowed = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $rootOrganizationalUnitToBeShadowed.DistinguishedName -SearchScope OneLevel  

# $organizationlUnitsToBeShadowed | select DistinguishedName | fl



$configuration = @()


# a recursive function to add an organizational unit and all sub-organizational units to the 
# configuration.
function processOrganizationalUnitToBeShadowed{
    param ($organizationalUnit, $ancestors=@())
    
    Write-Host ("     ")
    Write-Host ("Now processing " + $organizationalUnit.Name)
    # Write-Host ("existing configuration: ");     Write-Host ($script:configuration)
    
    $groupName = (@($ancestors | foreach-object {$_.Name}) + $organizationalUnit.Name) -Join "-"
    Write-Host ("groupName: " + $groupName)

    $configurationItem = [pscustomobject]@{
        Domain      =   (Get-ADDomain).DNSRoot;   
        ObjType     =   "user;computer";   
        SourceOU    =   $organizationalUnit.DistinguishedName;  
        DestOU      =   $shadowGroupsOrganizationalUnit.DistinguishedName ;    
        GroupName   =   $groupName ; 
        GroupType   =   "Security"; 
        Recurse     =   "SubTree" ;   
        Description =   "Shadow group automatically following the members of the organizational unit " + $organizationalUnit.DistinguishedName ; 
    }

    # Write-Host ("configurationItem: ")
    # Write-Host ($configurationItem)

    $script:configuration += $configurationItem

    $childOrganizationalUnits = Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase $organizationalUnit.DistinguishedName -SearchScope OneLevel 
    
    foreach($childOrganizationalUnit in $childOrganizationalUnits){
        processOrganizationalUnitToBeShadowed -organizationalUnit $childOrganizationalUnit -ancestors ($ancestors + $organizationalUnit)
    }
    
}

processOrganizationalUnitToBeShadowed -organizationalUnit $rootOrganizationalUnitToBeShadowed



$configuration | Export-Csv -NoTypeInformation -Force -Path $pathOfShadowGroupSyncConfigurationFile



# $action = New-ScheduledTaskAction `
    # -Execute 'Powershell.exe' `
    # -Argument "-NoProfile -WindowStyle Hidden -command `"`& '$pathOfShadowGroupSyncScript'  -file '$pathOfShadowGroupSyncConfigurationFile'  `""
$action = New-ScheduledTaskAction `
    -Execute 'Powershell.exe' `
    -Argument "-NoProfile -command `"`& '$pathOfShadowGroupSyncScript' -file '$pathOfShadowGroupSyncConfigurationFile' `" 2>&1 > `"$pathOfLogFile`""    
# $principal = New-ScheduledTaskPrincipal -Id "Author" -LogonType "S4U" -UserId $nameOfServiceUser 
# $principal = New-ScheduledTaskPrincipal `
    # -Id "Author" `
    # -LogonType [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.LogonTypeEnum]::S4U `
    # -UserId $serviceUser.DistinguishedName

#[Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.LogonTypeEnum].GetEnumNames()
    
# $principal = New-ScheduledTaskPrincipal `
    # -Id "Author" `
    # -LogonType S4U `
    # -UserId $serviceUser.DistinguishedName
    
# $principal = New-ScheduledTaskPrincipal `
    # -Id "Author" `
    # -LogonType Password `
    # -UserId $serviceUser.DistinguishedName
    
$principal = new-scheduledtaskprincipal `
    -id "author" `
    -logontype S4U `
    -userid $serviceuser.distinguishedname
    
# $principal = new-scheduledtaskprincipal `
    # -id "author" `
    # -logontype S4U `
    # -userid ((Get-ADDomain).Name + "\" + $serviceuser.Name)

# $principal = New-ScheduledTaskPrincipal
    
# $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At ( [System.DateTime] 0 )  -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Minutes 15)
# $trigger = New-ScheduledTaskTrigger -Once -At ( [System.DateTime] 0 ) -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Minutes 15)
# $trigger = New-ScheduledTaskTrigger -Once -At ( [System.DateTime] 0 )  -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval [System.TimeSpan]::MaxValue
#>>>   New-ScheduledTaskTrigger : Cannot process argument transformation on parameter 'RepetitionInterval'. Cannot convert value

# $trigger = New-ScheduledTaskTrigger -Once -At 9am  -RepetitionDuration (New-TimeSpan -Days 1) 
# it seems that when the repetition interval is not specified, we end up with a repetition interval of one day.


# $trigger = New-ScheduledTaskTrigger -Once -At 9am  -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan)
#>>   New-ScheduledTaskTrigger : The RepetitionInterval parameter value must be greater than 1 minute.


# $trigger = New-ScheduledTaskTrigger -Once -At ( [System.DateTime] 0 ) -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Minutes 15)
# the zero-datetime cuases an error when we register:  Register-ScheduledTask : The task XML contains a value which is incorrectly formatted or out of range.

# $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0) -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Minutes 15)
#the above works without errors, but we want a longer repetition duration
# $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0) -RepetitionDuration (New-TimeSpan -Days (100)) -RepetitionInterval (New-TimeSpan -Minutes 15)
# produces out-of-range error on registration
# $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0)  -RepetitionInterval (New-TimeSpan -Minutes 15)
#>>>   New-ScheduledTaskTrigger : The RepetitionInterval and RepetitionDuration Job trigger parameters must be specified together.

# # # # $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0)  -RepetitionInterval (New-TimeSpan -Minutes 15)
# # # # #apparently, in newr versions of the module, it is possible to omit the RepetitionDuration parameter to specify indefinite repetition.
# # # # # one-time update to latest version of the ScheduledTasks module:
# # # # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# # # # Update-Module -Force ScheduledTasks
# # # # Get-InstalledModule ScheduledTasks
# # # # Get-Module ScheduledTasks
# # # # Install-Module -Force ScheduledTasks
# # # # # # $trigger.RepetitionDuration = New-TimeSpan
# # # # # $trigger.RepetitionDuration = [System.TimeSpan]::MaxValue
# # # # # this causes the call to Register-ScheduledTask, below, to throw an error saying something about a value being out of range.

# # # # # $trigger.RepetitionDuration = (New-TimeSpan -Years 100)




# $trigger = New-ScheduledTaskTrigger `
    # -Daily  `
    # -DaysInterval 1 `
    # -At ( [System.DateTime] 0 )


# $trigger = New-ScheduledTaskTrigger `
    # -Daily  `
    # -DaysInterval 1 `
    # -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
    
# $trigger.RepetitionDuration = (New-TimeSpan -Days 1) 
# $trigger.RepetitionInterval = (New-TimeSpan -Minutes 15)

# $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0)  -RepetitionInterval (New-TimeSpan -Minutes 15)
try {
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0)  -RepetitionInterval (New-TimeSpan -Minutes 10)
} catch{
    #hack for Windows Serer 2012R2, which does not support specifying indefinite duration form powershell
    # we will have to go manualy edit the shceduled task in the gui to set the duration to indefinite.
    Write-Warning "We were unable to specify a scheduled task trigger with indefinite duration.  Please go manually edit the scheduled task and manually set the duration to indefinite."
    
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0)  -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration  (New-TimeSpan -Days 1)
}

$settingsSet = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
# Register-ScheduledTask -Action $action -Trigger $trigger -User $nameOfServiceUser -Settings $settingsSet -TaskName "shadowGroupSync" -Description "update the shadow security groups."
# Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settingsSet -TaskName "shadowGroupSync" -Description "update the shadow security groups."

$registeredScheduledTask = Get-ScheduledTask | Where-Object {$_.TaskName -eq $nameOfScheduledTask}
if($registeredScheduledTask ){
    # $scheduledTask | Unregister-ScheduledTask -Force
    $registeredScheduledTask | Unregister-ScheduledTask -Confirm:$false
}

$scheduledTask = New-ScheduledTask `
    -Action $action `
    -Description $descriptionOfScheduledTask `
    -Principal $principal `
    -Settings $settingsSet `
    -Trigger $trigger 

#works:
Register-ScheduledTask `
    -InputObject $scheduledTask  `
    -TaskName $nameOfScheduledTask `
    -User $nameOfServiceUser `
    -Password $passwordOfServiceUser

#does not work: Register-ScheduledTask : The supplied variant structure contains invalid data.
# Register-ScheduledTask `
    # -InputObject $scheduledTask  `
    # -TaskName $nameOfScheduledTask `
    # -Password $passwordOfServiceUser

#works: 
# Register-ScheduledTask `
    # -InputObject $scheduledTask  `
    # -TaskName $nameOfScheduledTask `
    # -User $nameOfServiceUser 
#########################################################################################################


$registeredScheduledTask = Get-ScheduledTask | Where-Object {$_.TaskName -eq "shadowGroupSync"}


$report = ""

$report += @"
The '$nameOfScheduledTask' scheduled task will run under the authority of the following credentials:
username:   $($serviceUser.Name)
password:   $passwordOfServiceUser


`$registeredScheduledTask:  
$( $registeredScheduledTask            | fl | out-string)


`$registeredScheduledTask.Principal:
$( $registeredScheduledTask.Principal  | fl | out-string)

`$registeredScheduledTask.Actions: 
$( $registeredScheduledTask.Actions    | fl | out-string)

`$registeredScheduledTask.Settings:
$( $registeredScheduledTask.Settings   | fl | out-string)

`$registeredScheduledTask.Triggers:
$( $registeredScheduledTask.Triggers   | fl | out-string)

`$registeredScheduledTask.Triggers.Repetition:
$( $registeredScheduledTask.Triggers.Repetition   | fl | out-string)



`$scheduledTask:  
$( $scheduledTask            | fl | out-string)


`$scheduledTask.Principal:
$( $scheduledTask.Principal  | fl | out-string)

`$scheduledTask.Actions: 
$( $scheduledTask.Actions    | fl | out-string)

`$scheduledTask.Settings:
$( $scheduledTask.Settings   | fl | out-string)

`$scheduledTask.Triggers:
$( $scheduledTask.Triggers   | fl | out-string)

`$scheduledTask.Triggers.Repetition:
$( $scheduledTask.Triggers.Repetition   | fl | out-string)



"@
  



# Principal.LogonType As Integer
# Set to one of the following TASK_LOGON TYPE enumeration constants.
# Property value
# Value 	Meaning

# TASK_LOGON_NONE
# 0

	# The logon method is not specified. Used for non-NT credentials.

# TASK_LOGON_PASSWORD
# 1

	# Use a password for logging on the user. The password must be supplied at registration time.

# TASK_LOGON_S4U
# 2

	# Use an existing interactive token to run a task. The user must log on using a service for user (S4U) logon. When an S4U logon is used, no password is stored by the system and there is no access to either the network or encrypted files.

# TASK_LOGON_INTERACTIVE_TOKEN
# 3

	# User must already be logged on. The task will be run only in an existing interactive session.

# TASK_LOGON_GROUP
# 4

	# Group activation. The userId field specifies the group.

# TASK_LOGON_SERVICE_ACCOUNT
# 5

	# Indicates that a Local System, Local Service, or Network Service account is being used as a security context to run the task.

# TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD
# 6

	# First use the interactive token. If the user is not logged on (no interactive token is available), then the password is used. The password must be specified when a task is registered. This flag is not recommended for new tasks because it is less reliable than TASK_LOGON_PASSWORD.

# clear;

Write-Output $report

 