$http_passfields = 'ahd_password','pass','password','_password','passwd','session_password','sessionpassword','login_password','loginpassword','form_pw','userpassword','pwd','upassword','login_password','passwort','passwrd','wppassword','upasswd','j_password'
$http_userfields = 'login','wpname','ahd_username','unickname','nickname','user','user_name','alias','pseudo','email','username','_username','userid','form_loginname','loginname','login_id','loginid','session_key','sessionkey','pop_login','user_id','screename','uname','ulogin','acctname','account','member','mailaddress','membername','login_username','login_email','loginusername','loginemail','sign-in','j_username'
$dontDot = 'pw','uid','id','uin', 'log'
$cc_regex1 = "^([4-6][0-9][0-9][0-9])\-([0-9][0-9][0-9][0-9])\-([0-9][0-9][0-9][0-9])\-([0-9][0-9][0-9][0-9])"
# Take in arg to set location of pcap files.
$pcapDirectory = 'H:\ASPTT\Pentest\2018\SPA\Gabe_SD5166399'
$pcapList = Get-ChildItem $pcapDirectory
$dotArrayStrings = @()

function String-Fu ($dotArrayStrings){
    foreach ($string in $http_userfields){
        $stringArray = $string -Split ''
        $newString = ""
        # add . between each character in the stringArray.
        foreach ($char in $stringArray) {
            $newString += ($char + ".")
        }
        # Trim last . from string.
        $newString = $newString.TrimStart('.')
        $newString = $newString.TrimEnd('.')
        $dotArrayStrings += $newString
    }

    foreach ($string in $http_passfields){
        $stringArray = $string -Split ''
        $newString = ""
        # add . between each character in the stringArray.
        foreach ($char in $stringArray) {
            $newString += ($char + ".")
        }
        # Trim last . from string.
        $newString = $newString.TrimStart('.')
        $newString = $newString.TrimEnd('.')
        $dotArrayStrings += $newString
    }
    Return $dotArrayStrings
}

$dotArray = String-Fu($dotArrayStrings)

# combine the arrays
$bulkArray = $dotArray + $http_passfields + $http_userfields + $dontDot

foreach ($pcap in $pcapList){
    if ($pcap.Name -like "*PCAP"){
        $pcapName = $pcap.Name
        Write-Host $pcapName
        $notFound = "H:\ASPTT\Powershell_Scripts\TShark_Test_Double_Check_$pcapName.txt"
        $outFile = "H:\ASPTT\Powershell_Scripts\TShark_Test_Interesting_$pcapName.txt"
        $pcapName | Out-File $outFile -Append

        # Get number of tcp streams:
        $numArray = C:\'Program Files'\Wireshark\tshark.exe -nlr $pcapDirectory\$pcap -Y tcp.flags.syn==1 -T fields -e tcp.stream
        $numMax = $numArray[-1]
        Write-Host $numMax

        # loop through each stream getting the data in ascii
        foreach ($i in 0..$numMax){
            $results = C:\'Program Files'\Wireshark\tshark.exe -r $pcapDirectory\$pcap -q -z follow,tcp,ascii,$i
            $results = [system.String]::Join(" ", $results)
            if ($results -eq ""){}
            else {
                $inInteresting = 0
                #$triggered = 0
                $itemCount = 0
                foreach ($item in $bulkArray){
                    $itemCount += 1
                    if ($results -match $item){
                        "Flagged on the following word: " + $item | Out-File $outFile -Append
                        $inInteresting += 1
                    }
                    elseif ($inInteresting -eq 0 -and $itemCount -eq $bulkArray.Count) {
                       #$triggered += 1
                        $results | Out-File $notFound -Append
                    }
                }
                if ($inInteresting -gt 0) {
                    $results | Out-File $outFile -Append
                }
            }
            Write-Progress -Activity "Looping through TCP Streams..." -Status "Completed $i of $numMax" -PercentComplete (($i/$numMax)*100)
        }
    }
}