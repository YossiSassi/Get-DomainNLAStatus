# Get-DomainNLAStatus
# Comments to yossis@cyberartsecurity.com
[cmdletbinding()]
param (
    [Boolean]$PingHostBeforeQuery = $true,
    [Boolean]$AllOSVersions = $false
)

$Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$Searcher.PropertiesToLoad.AddRange(@("operatingsystem","name","distinguishedname"))

switch ($AllOSVersions)
    {
        $true {
            $Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(serviceprincipalname=*TERM*))"
            #$Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|(OperatingSystem=*Windows 10*)(OperatingSystem=*Windows Server*))(serviceprincipalname=*TERM*))"            

            $DisabledComputers = ([adsisearcher]"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2)(serviceprincipalname=*TERM*))").FindAll()
        }

        $false { # Default. query NLA level only for older OS - WinXP/Vista/7/2003/2008
            $Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|(OperatingSystem=*Windows XP*)(OperatingSystem=*Windows Vista*)(OperatingSystem=*Windows 7*)(OperatingSystem=*Windows 2003*)(OperatingSystem=*Windows 2008*))(serviceprincipalname=*TERM*))"
            #$Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|(OperatingSystem=*Windows 10*)(OperatingSystem=*Windows Server*))(serviceprincipalname=*TERM*))"            

            $DisabledComputers = ([adsisearcher]"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2)(|(OperatingSystem=*Windows XP*)(OperatingSystem=*Windows Vista*)(OperatingSystem=*Windows 7*)(OperatingSystem=*Windows 2003*)(OperatingSystem=*Windows 2008*))(serviceprincipalname=*TERM*))").FindAll()
        }
    }

$Searcher.PageSize = 10000 # by default, 1000 are returned for adsiSearcher. We set it to handle up to 10K acccounts
$Computers = ($Searcher.Findall())

if ($Computers.Count -eq 0) {
        switch ($AllOSVersions)
            {
                $true {
                    Write-Host "[!] Domain contains No ENABLED Computer Accounts with RDP SPNs. Quiting" -BackgroundColor Green -ForegroundColor White;
                }
                
                $false {
                    Write-Host "[!] Domain contains No WinXP/Vista/7/2003/2008 ENABLED Computer Accounts with RDP SPNs. Quiting" -BackgroundColor Green -ForegroundColor White;
                }
            }
        
        if ($DisabledComputers.Count -gt 0) {
            Write-Host "[!] Found $($DisabledComputers.Count) DISABLED Computer account(s) - recommended that you handle them as well:" -BackgroundColor Red -ForegroundColor White;
            $DisabledComputers.Properties.distinguishedname | more;
            }

        break;
    }

switch ($AllOSVersions)
    {
        $true {
            Write-Host "[!] Found $($Computers.Count) Enabled Computer Account(s) with RDP SPNs." -BackgroundColor Green -ForegroundColor White
        }

        $false {
            Write-Host "[!] Found $($Computers.Count) winXP/Vista/7/2003/2008 Enabled Computer Account(s) with RDP SPNs." -BackgroundColor Green -ForegroundColor White
        }
    }

#(gwmi win32_service -ComputerName lon-cl1 | ? name -eq "RemoteREgistry").stopservice()
#Set-Service "RemoteRegistry" -ComputerName lon-cl1 -StartupType Manual

$CurrentEAP = $ErrorActionPreference;
$Erroraction = "Stop";

[int]$NLA0 = 0; [int]$NLA1 = 0; [int]$NLA2 = 0;

# NOTE: Default timeout for ping is 20ms - Can change it in the following function below
filter Invoke-Ping {(New-Object System.Net.NetworkInformation.Ping).Send($_,20)}

$Results = $Computers | foreach {
    $Obj = New-Object psobject;
    $Obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value "$($_.Properties.name)"
    $Obj | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value "$($_.Properties.operatingsystem)"
    $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value "$($_.Properties.distinguishedname)"
    $Obj
    $Obj = $null
}
Clear-Variable Computers

$Results | foreach {
    Try 
        {

        $Obj = $_;

        Write-Host "[!] Querying $($Obj.ComputerName)... " -NoNewline

        switch ($PingHostBeforeQuery)
            {
                $true {$ProceedToQuery = ($Obj.ComputerName | Invoke-Ping).status -eq "Success"}
                $false {$ProceedToQuery = $true}
            }

        if ($ProceedToQuery) {

            $RDPregKey = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            $RegValue = 'SecurityLayer'            

            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Obj.ComputerName)
    
            if ($?) # No error raised. continue.
                {
                $Regkey = $Reg.opensubkey($RDPregKey)
                $Value = $Regkey.GetValue($RegValue)
    
                switch ($value)
                    {
                        0 {
                            # Low security level: RDP is used by the client for authentication prior to a remote desktop connection being established. Vulnerable to Blue Keep!
                            Write-Host "Low Security/Vulnerable (No NLA)" -BackgroundColor Red -ForegroundColor White
                            $NLA0++
                            $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "LowSecurity(0)" -Force
                            }
                        1 {
                            # Medium security level: Default setting. Server and Client negotiate the method for authentication prior to a RDP connection being established. Use this setting only if all your machines are running Windows & none is set to 0
                            Write-Host "Medium Security - Potentially vulnerable" -ForegroundColor Yellow
                            $NLA1++
                            $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "MediumSecurity(1)" -Force
                            }
                        2 {
                            # high security level: TLS is used by Server and Client prior to a RDP connection being established.
                            Write-Host "NLA is Enabled" -ForegroundColor Green
                            $NLA2++
                            $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "HighSecurity(2)" -Force
                            }
                    }
                Clear-Variable reg, regkey, Value
                }
            }
        else 
        {
            "No response to ping"
            $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "NoResponse" -Force
        }
    }        

        Catch { # Cannot open Reg Key. Could be connectivity issues etc
            $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "Error" -Force
            Switch ($Error[0].Exception.HResult)
                {
                    -2146233087 {Write-Host "The network path was not found"}
                    default {Write-Host $Error[0].Exception.Message -ForegroundColor cyan}
                }       
        }
}

if ($DisabledComputers.Count -gt 0) {
            $DisabledComputers | foreach {
                $Obj = New-Object psobject;
                $Obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value "$($_.Properties.name)"
                $Obj | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value "$($_.Properties.operatingsystem)"
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value "$($_.Properties.distinguishedname)"
                $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "DISABLED_Account_Potentially_Vulnerable"
                $Results += $Obj
                $Obj = $null;
                }
            }

$ReportName = "$ENV:Temp\NLA-Check_$(Get-Date -Format ddMMyyyyHHmmss).csv"
$Results | Export-Csv $ReportName

Write-Host "`n[!] Done.`n" -BackgroundColor Green -ForegroundColor White
Write-Host "[!] Found $NLA0 computers with Low Security/Vulnerable, $NLA1 computers with Medium Security/Potentially Vulnerable, and $NLA2 computers with NLA Enabled/Secured." -ForegroundColor Cyan

if ($DisabledComputers.Count -gt 0) {
    Write-Host "[!] Found $($DisabledComputers.Count) DISABLED Computer account(s) - recommended that you handle them as well." -BackgroundColor Red -ForegroundColor White;
}

Write-Host "[!] Results saved to $ReportName" -ForegroundColor DarkYellow

$ErrorActionPreference = $CurrentEAP
