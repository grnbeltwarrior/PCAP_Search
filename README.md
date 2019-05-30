# PCAP_Search
Powershell script for leveraging tshark for pcap tcp stream string searching.
Perhaps I'll get around to recreating Pcredz using something like this.


# TCP_Stream_Output.ps1:
Using workflow to do some parallel processing of outputting TCP streams for all the pcap files within a defined directory. Creates a new directory of the pcap name with another directory for the stream (ASCII) text files. Then you could do some string searching of the text files, or use the PowershellGrep within https://github.com/grnbeltwarrior/PowerShare_Grep script to automate the searching.
