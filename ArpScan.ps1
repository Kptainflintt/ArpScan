#Vérification du statut d'Administrateur. Si le script n'as pas été lancé en admin, ouverture d'un nouveau processus. Merci à l'auteur que je n'ai malheureusement pu retrouver tant il a été copié...
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}


Write-Host "Ce script s'execute en Administrateur" -foregroundcolor "yellow"

#Selection de l'interface pour le scan
Get-NetIpaddress |where {($_.PrefixLength -ne 64) -and ($_.PrefixLength -ne 128)} | Format-Table -Property ifIndex,IPAddress

$index = Read-Host "Tapez le numéro d'index de la carte réseau"
$Address = Get-NetIPAddress | where {($_.ifIndex -eq $index) -and ($_.AddressFamily -eq "IPv4")} | Select-Object -ExpandProperty IPAddress
$Mask = Get-NetIPAddress | where {($_.ifIndex -eq $index) -and ($_.AddressFamily -eq "IPv4")} | Select-Object -ExpandProperty PrefixLength

# Sélection de la partie réseau
if ($Mask -eq 24){
$Network = $Address.Split(".")[0,1,2] -join '.'
$Subnet = 1..254 | % {"$Network.$_"}
}
elseif ($Mask -eq 16){
$Network = $Address.Split(".")[0,1] -join '.'
$Range = 0..254 | % {"$Network.$_"}
$Subnet = foreach ($IPs in $Range) {
          1..254 | % {"$IPs.$_"} #-OutVariable Subnet | Out-Null
          }
}
elseif ($Mask -eq 8){
$Network = $Address.Split(".")[0] -join '.'
$Range = 0..254 | % {"$Network.$_"}
$Subnet = foreach ($IPs in $Range) {
          0..254 | % {"$IPs.$_"} -OutVariable Sub1 | Out-Null
            Foreach ($Piece in $Sub1){
                1..254 | % {"$Piece.$_"} #-OutVariable Subnet | Out-Null
            }
    }
}
else {
Write-Host "Votre masque de sous réseau ne permet pas d'utiliser ce script (en cours d'amélioration)"
continue 
}

#Vider le cache ARP
netsh interface ip delete arpcache
Write-Host "Cache ARP supprimé" -ForegroundColor "yellow"

#Scan UDP
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
$Bytes = $ASCIIEncoding.GetBytes("a")
$UDP = New-Object System.Net.Sockets.Udpclient
$counter = 0
#$Subnet | ForEach-Object {
Foreach ($addr in $Subnet){
        $UDP.Connect($addr,1)
        [void]$UDP.Send($Bytes,$Bytes.length)
        #Write-Progress -Activity "Scan de $addr"
        $counter++
        Write-Progress -Activity 'Scan en cours' -CurrentOperation $addr -PercentComplete (($counter / $Subnet.count) * 100)
        #Start-Sleep -Milliseconds 200
          }


$Hosts = arp -a


    $Hosts = $Hosts | Where-Object {$_ -match "dynamique"} | % {($_.trim() -replace " {1,}",",") | ConvertFrom-Csv -Header "IP","MACAddress"}
    $Hosts = $Hosts | Where-Object {$_.IP -in $Subnet}

    Write-Output $Hosts

