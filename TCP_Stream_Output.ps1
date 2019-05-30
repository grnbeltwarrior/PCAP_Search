workflow Start-PCAP-Stream-Ripper {
    $pcapDirectory = 'D:\Pentesting\PCAPs\'
    $pcapList = Get-ChildItem $pcapDirectory
    foreach -Parallel ($pcap in $pcapList) {
        InlineScript{
            if ($Using:pcap.Name -like "*PCAP"){
                # Get file name (example asdf.pcap)
                $pcapName = $Using:pcap.Name
                # Get file name, split or strip '.' (example asdf)
                $name = ($pcapName.split('.')[0])
                # Set path to store the stream results
                $ResultsPath = "$Using:pcapDirectory\$name\Streams"
                Write-Host "Processing packet capture file: $Using:pcap"
                # Get number of tcp streams:
                $numArray = C:\'Program Files'\Wireshark\tshark.exe -nlr $Using:pcapDirectory\$Using:pcap -Y tcp.flags.syn==1 -T fields -e tcp.stream
                $numMax = $numArray[-1]
            
                # The main TCP Stream component.
                # loop through each stream getting the data in ascii
                foreach ($i in 0..$numMax){
                    $results = C:\'Program Files'\Wireshark\tshark.exe -r $Using:pcapDirectory\$Using:pcap -q -z follow,tcp,ascii,$i
                    $results = [system.String]::Join(" ", $results)
                    if ($results -eq ""){}
                    else {
                        # Create a directory for the streams.
                        if (Test-Path -Path $ResultsPath -PathType Container) {}
                        else {
                            New-Item -Path $ResultsPath -ItemType directory | Out-Null
                        }
                        $outfile = "$ResultsPath\$Using:pcap'_TCP_Stream_'$i.txt"
                        $results | Out-File $outfile
                    }
                    Write-Progress -Activity "Looping through TCP Streams..." -Status "Completed $i of $numMax" -PercentComplete (($i/$numMax)*100)
                }
            }
            else {}
        }
    }
}
Start-PCAP-Stream-Ripper
