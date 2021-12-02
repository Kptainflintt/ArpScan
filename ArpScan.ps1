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


#Write-Host "Ce script s'execute en Administrateur" -foregroundcolor "yellow"
1..2 | % -begin {cls} -process {Write-Host "-----!!Ce script s'execute en Administrateur!!-----" -ForegroundColor "yellow";sleep 1;cls;sleep 1}

Write-Host "1. Scan selon une plage entrée manuellement"
Write-Host "2. Scan selon une interface"

$choice = Read-Host "Votre choix"

if ($choice -eq 1) {
    Write-Host "Attention, scanner une grande plage IP risque de donner des résultats faussés. Les entrées ARP ayant une durée courte!" -ForegroundColor "red"
    $Address1 = Read-Host "Adresse de début"
    $Address2 = Read-Host "Adresse de fin"
    [int]$oct1 ,[int]$oct2 ,[int]$oct3 ,[int]$oct4 = $Address1.Split(".")
    [int]$oct1b , [int]$oct2b ,[int]$oct3b ,[int]$oct4b = $Address2.Split(".")
        if ($oct2 -ne $oct2b){
        $Range = $oct2..$oct2b | % {"$oct1.$_"}
        $Sub1 = foreach ($IPs in $Range) {
                $oct3..$oct3b | % {"$IPs.$_"}
                }
        $Subnet += Foreach ($Piece in $Sub1){
                   $oct4..$oct4b | % {"$Piece.$_"}
                    if ($Subnet -ne $Address2) {
                    continue
                    }
                    else {
                    break
                    }
                   }
        }
        elseif ($oct3 -ne $oct3b){
        $Range = $oct3..$oct3b | % {"$oct1.$oct2.$_"}
        $Subnet += foreach ($IPs in $Range) {
                   $oct4..254 | % {"$IPs.$_"}
                    if ($Subnet -ne $Address2) {
                    continue
                    }
                    else {
                    break
                    }
                   }
        }
        else {
        $Range = "$oct1.$oct2.$oct3"
        $Subnet = $oct4..$oct4b | % {"$Range.$_"}
        }
}


elseif ($choice -eq 2) {
    #Selection de l'interface pour le scan
    Get-NetIpaddress |where {($_.PrefixLength -ne 64) -and ($_.PrefixLength -ne 128)} | Format-Table -Property ifIndex,IPAddress
    $index = Read-Host "Tapez le numéro d'index de la carte réseau"
    
    #Déclaration des variables
    $Address = Get-NetIPAddress | where {($_.ifIndex -eq $index) -and ($_.AddressFamily -eq "IPv4")} | Select-Object -ExpandProperty IPAddress
    $Mask = Get-NetIPAddress | where {($_.ifIndex -eq $index) -and ($_.AddressFamily -eq "IPv4")} | Select-Object -ExpandProperty PrefixLength
    
    # Decoupage de l'adresse d'interface en fonction du masque
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
    Write-Host "Masque non supporté, merci de faire le choix n°1"
    continue 
    }
}

else {
Write-Host "Mauvaise saisie, arrêt du script"
Break
}

#Vider le cache ARP
netsh interface ip delete arpcache
Write-Host "Cache ARP supprimé" -ForegroundColor "yellow"

#Scan UDP sur les adresses de la variable
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
$Bytes = $ASCIIEncoding.GetBytes("a")
$UDP = New-Object System.Net.Sockets.Udpclient
$counter = 0
#$Subnet | ForEach-Object {
Foreach ($addr in $Subnet){
        $UDP.Connect($addr,1)
        [void]$UDP.Send($Bytes,$Bytes.length)
        #Ajout d'une barre de progression
        $counter++
        Write-Progress -Activity 'Scan en cours' -CurrentOperation $addr -PercentComplete (($counter / $Subnet.count) * 100)
        #Start-Sleep -Milliseconds 200
          }

#Affichage de la nouvelle table ARP et insertion dans une variable
$Hosts = arp -a

    #Tri et mise en forme
    $Hosts = $Hosts | Where-Object {$_ -match "dynamique"} | % {($_.trim() -replace " {1,}",",") | ConvertFrom-Csv -Header "IP","MACAddress"}
    $Hosts = $Hosts | Where-Object {$_.IP -in $Subnet}

    Write-Output $Hosts

