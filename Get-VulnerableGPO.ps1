<#
.Synopsis
   v1. Written by Darren Mar-Elia (github.com/gpoguy), Semperis (https://semperis.com), 2018. Searches GPOs that have sensitive security settings in them, that grant Authenticated Users read access
.DESCRIPTION
   Searches GPOs that have sensitive security settings in them, that grant Authenticated Users read access (i.e. World Readable GPOs)
   The goal is to call out GPOs that contains settings that grant privileged access, so that their delegation can be modified to prevent 
   attackers from easily determining where privileged access is granted in your environment. 
   This function requires the free SDM GPMC PowerShell Module, which can be downloaded from: https://s3.amazonaws.com/sdmsoftware.com/dl/SDM-GPMC-Module2.0Setup.zip
   which is used to parse settings across suspect GPOs. The function requires read access to GPOs in order to succeeed.
   Time to run varies based on how big the environment is, but took about 35 minutes to run in a GPO test environment of 500 GPOs, with a robust collection of settings

.EXAMPLE
   Get-VulnerableGPO
.EXAMPLE
   Get-VulnerableGPO -Domain cpandl.com
#>

Add-Type -AssemblyName System.DirectoryServices.Protocols
Import-Module SDM-GPMC
$secGPOs
$lugsGPOs
function Get-VulnerableGPO
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Provide a DNS domain name other than the default one
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Domain
  
    )
    
    Begin
    {
        #$startTime = [DateTime]::Now
        #$startTime


        if ($Domain -eq $null)
        {
            $Domain = $env:USERDNSDOMAIN
        } 
        $DN = GetDN $Domain
        $GPCContainer = "CN=Policies, CN=System, "+$DN
        #first, find the GPOs that contain security or GP Preferences Local Users and Groups by searching for the appropriate CSEs
        $secGPOs =ADFind $Domain "displayName","gpcMachineExtensionNames" $GPCContainer "OneLevel" "(&(objectClass=groupPolicyContainer)(gpcMachineExtensionNames=*{827D319E-6EAC-11D2-A4EA-00C04F79F83A}*))" 1000
        $lugsGPOS = ADFind $Domain "displayName","gpcMachineExtensionNames" $GPCContainer "OneLevel" "(&(objectClass=groupPolicyContainer)(gpcMachineExtensionNames=*{17D89FEC-5C44-4972-B12D-241CAEF74509}*))" 1000
    }
    Process
    {
        #now use SDM GP module to find vulnerable GPOs (i.e. grant Authn Users Read access and also contain privileged policy settings)
        #we will look for the following policies that grant some kind of privileged access
        #Restricted Groups policy that controls Local Administrators or Power Users
        #User Rights Assignment that grants Debug Progams, Load/Unload Device Drivers and Take Ownership
        #GPP Local Users and Groups policy that controls Local Administrators or Power Users
        #First set up the setting Paths we care about looking for:
        $AreasPol =@{}
        $AreasPref = @{}
        $AreasPol.Add("Computer Configuration|Policies|Windows Settings|Security Settings|Restricted Groups|BUILTIN\Administrators|Members","Restricted Groups--Administrators")
        $AreasPol.Add("Computer Configuration|Policies|Windows Settings|Security Settings|Restricted Groups|BUILTIN\Power Users|Members","Restricted Groups--Power Users")
        $AreasPol.Add("Computer Configuration|Policies|Windows Settings|Security Settings|Local Policies|User Rights Assignment|Debug programs","User Rights Assignment--Debug Programs")
        $AreasPol.Add("Computer Configuration|Policies|Windows Settings|Security Settings|Local Policies|User Rights Assignment|Load and unload device drivers","User Rights Assignment--Load/Unload Device Drivers")
        $AreasPol.Add("Computer Configuration|Policies|Windows Settings|Security Settings|Local Policies|User Rights Assignment|Take ownership of files or other objects","User Rights Assignment--Take Ownership")
        
        $AreasPref.Add("Computer Configuration|Preferences|Control Panel Settings|Local Users and Groups|Group: Administrators (built-in)|Add members","GPP Local Users & Groups--Administrators")
        $AreasPref.Add("Computer Configuration|Preferences|Control Panel Settings|Local Users and Groups|Group: Power Users (built-in)|Add members","GPP Local Users & Groups--Power Users")


              
        
        #first process the security CSE GPOs
        foreach ($foundGPO in $secGPOs)
        {
            #now check to see if the GPO has vulnerable delegation, which means Authn Users, Read or ReadApply--otherwise we don't care
            if ($foundGPO.Attributes -eq $null)
            {
                continue
            }
            $perms = Get-SDMGPOSecurity -DisplayName $foundGPO.Attributes["displayName"][0] -Domain $Domain
            [bool]$found = $false
            foreach ($ACE in $perms)
            {
                if ($ACE.Trustee -eq "NT AUTHORITY\Authenticated Users" -and ($ACE.Permission -eq "permGPOApply" -or $ACE.Permission -eq "permGPORead"))
                {
                    $found = $true
                    break
                }
                
            }
            if ($found -eq $false)
            {
                continue
            }
            $object = New-Object PSObject
            Add-Member -InputObject $object -MemberType NoteProperty -Name GPOName -Value ""
            Add-Member -InputObject $object -MemberType NoteProperty -Name PolicyArea -Value ""
            Add-Member -InputObject $object -MemberType NoteProperty -Name Permission -Value ""

            #generate settings for current GPO
            $settings = Out-SDMGPSettings -Domain $Domain -DisplayName $foundGPO.Attributes["displayName"][0] -Areas "Security"
            #now search for our settings
            foreach ($item in $settings)
            {
                foreach ($area in $AreasPol.Keys)
                {
                    if ($item.SettingPath -eq $area)
                    {
                        if ($object.PolicyArea -ne $AreasPol[$area]) #only add this one if we haven't found it already
                        {
                                
                            
                                    $object.GPOName = $foundGPO.Attributes["displayName"][0]
                                    $object.PolicyArea = $AreasPol[$area]
                                    $object.Permission = "Authenticated Users"+":"+$ACE.Permission
                                    $object
                                    break

                        }
                    
                    
                    }
                }
                
            }
            

            
        }
        # now process the LUGs settings
        foreach ($foundGPO in $lugsGPOs)
        {
            if ($foundGPO.Attributes -eq $null)
            {
                continue
            }
            #now check to see if the GPO has vulnerable delegation, which means Authn Users, Read or ReadApply--otherwise we don't care
            $perms = Get-SDMGPOSecurity -DisplayName $foundGPO.Attributes["displayName"][0] -Domain $Domain
            [bool]$found = $false
            foreach ($ACE in $perms)
            {
                if ($ACE.Trustee -eq "NT AUTHORITY\Authenticated Users" -and ($ACE.Permission -eq "permGPOApply" -or $ACE.Permission -eq "permGPORead"))
                {
                    $found = $true
                    break
                }
                
            }
            $object = New-Object PSObject
            Add-Member -InputObject $object -MemberType NoteProperty -Name GPOName -Value ""
            Add-Member -InputObject $object -MemberType NoteProperty -Name PolicyArea -Value ""
            Add-Member -InputObject $object -MemberType NoteProperty -Name Permission -Value ""

            $settings = Out-SDMGPSettings -Domain $Domain -DisplayName $foundGPO.Attributes["displayName"][0] -Areas "Local Users and Groups"
            #now search for our settings
            foreach ($item in $settings)
            {
                foreach ($area in $AreasPref.Keys)
                {
                    if ($item.SettingPath.Contains($area))
                    {
                        if ($object.PolicyArea -ne $AreasPref[$area]) #only add this one if we haven't found it already
                        {
                            
                            $object.GPOName = $foundGPO.Attributes["displayName"][0]
                            $object.PolicyArea = $AreasPref[$area]
                            $object.Permission = "Authenticated Users"+":"+$ACE.Permission
                            $object

                            break

                        }
                    
                    }
                }
                
            }
            
        }
                   
    }
    End
    {
       # $endTime = [DateTime]::Now
       # $endTime
        
    }
}
function ADFind #using System.DS.Protocols to do LDAP searches of GPCs
{
    param(
        [string]$dnsDomain,[string[]]$attributes, [string]$baseDN,[System.DirectoryServices.Protocols.SearchScope]$scope, [string]$filter,[int]$pageSize
    )

    $results = new-object "System.Collections.Generic.List[System.DirectoryServices.Protocols.SearchResultEntry]"
    [System.DirectoryServices.Protocols.LdapConnection] $conn = new-object System.DirectoryServices.Protocols.LdapConnection($dnsDomain) 
    [System.DirectoryServices.Protocols.SearchRequest] $search = new-object System.DirectoryServices.Protocols.SearchRequest($baseDN,$filter,$scope,$attributes)
    [System.DirectoryServices.Protocols.PageResultRequestControl] $pageRequest = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
    $search.Controls.Add($pageRequest) 

    [System.DirectoryServices.Protocols.SearchOptionsControl] $searchOptions = new-object System.DirectoryServices.Protocols.SearchOptionsControl([System.DirectoryServices.Protocols.SearchOption]::DomainScope)
    $search.Controls.Add($searchOptions)
    [int] $pageCount = 0
    while ($true)
    {
      $pageCount++ 
      [System.DirectoryServices.Protocols.SearchResponse] $response = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($search) 
      [System.DirectoryServices.Protocols.PageResultResponseControl] $pageResponse = [System.DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
      if ($response.Entries.Count -gt 0)
      {
          foreach ($entry in $response.Entries)
          {
            $results.Add($entry)
          }
     
      }
      if ($pageResponse.Cookie.Length -eq 0)
      {
        break
      }
      $pageRequest.Cookie = $pageResponse.Cookie
    
    }
    return $results

     
    
}

function GetDN #calculates Distinguished Name 
{
    param(
        [string]$dnsDomain
    )
    $domContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $dnsDomain);
    $selectedDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domContext);
    return $selectedDomain.GetDirectoryEntry().Properties["distinguishedName"][0].ToString();

}

Get-VulnerableGPO