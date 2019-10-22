#This script will generate the JSON extractor needed to parse PAN-OS syslog into something useful in Graylog
#Strings are taken from https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions.html
$PANOSVersion = "9.0"
$OutputPath = "C:\Temp\$PANOSVersion.json"

#Get the strings into objects
$TrafficString = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol, Action, Bytes, Bytes Sent, Bytes Received, Packets, Start Time, Elapsed Time, Category, FUTURE_USE, Sequence Number, Action Flags, Source Location, Destination Location, FUTURE_USE, Packets Sent, Packets Received, Session End Reason, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Action Source, Source VM UUID, Destination VM UUID, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, SCTP Association ID, SCTP Chunks, SCTP Chunks Sent, SCTP Chunks Received, UUID for rule, HTTP/2 Connection"
$ThreatString = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol, Action, URL/Filename, Threat ID, Category, Severity, Direction, Sequence Number, Action Flags, Source Location, Destination Location, FUTURE_USE, Content Type, PCAP_ID, File Digest, Cloud, URL Index, User Agent, File Type, X-Forwarded-For, Referer, Sender, Subject, Recipient, Report ID, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE, Source VM UUID, Destination VM UUID, HTTP Method, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, Threat Category, Content Version, FUTURE_USE, SCTP Association ID, Payload Protocol ID, HTTP Headers, URL Category List, UUID for rule, HTTP/2 Connection"
$ConfigString = "FUTURE_USE, Receive Time, Serial Number, Type, Subtype, FUTURE_USE, Generated Time, Host, Virtual System, Command, Admin, Client, Result, Configuration Path, Before Change Detail, After Change Detail, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name"
$SystemString = "FUTURE_USE, Receive Time, Serial Number, Type, Content/Threat Type, FUTURE_USE, Generated Time, Virtual System, Event ID, Object, FUTURE_USE, FUTURE_USE, Module, Severity, Description, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name"

$TrafficValues = $TrafficString.Split(",")
$ThreatValues = $ThreatString.Split(",")
$ConfigValues = $ConfigString.Split(",")
$SystemValues = $SystemString.Split(",")

#Declare the bits that go at the start and end
$Start = @"
{
    "extractors": [

"@
$End = @"
],
"version": "3.1.2"
}
"@

#Work out all the traffic strings
$TrafficResult = ""
$Index = 1

foreach($value in $TrafficValues){
    $value = $value.trim().replace(" ","").replace("/","").replace("_","").replace("IP","_IP")
    if($value -ne "FUTUREUSE"){
    $TrafficResult += @"
    {
        "title": "$value",
        "extractor_type": "split_and_index",
        "converters": [],
        "order": 0,
        "cursor_strategy": "copy",
        "source_field": "message",
        "target_field": "$value",
        "extractor_config": {
          "index": $Index,
          "split_by": ","
        },
        "condition_type": "string",
        "condition_value": ",TRAFFIC,"
      },

"@
    }
    $Index++
}

#Work out all the threat strings
$ThreatResult = ""
$Index = 1

foreach($value in $ThreatValues){
    $value = $value.trim().replace(" ","").replace("/","").replace("_","").replace("IP","_IP")
    if($value -ne "FUTUREUSE"){
    $ThreatResult += @"
    {
        "title": "$value",
        "extractor_type": "split_and_index",
        "converters": [],
        "order": 0,
        "cursor_strategy": "copy",
        "source_field": "message",
        "target_field": "$value",
        "extractor_config": {
          "index": $Index,
          "split_by": ","
        },
        "condition_type": "string",
        "condition_value": ",THREAT,"
      },

"@
    }
    $Index++
}

#Work out all the config strings
$ConfigResult = ""
$Index = 1

foreach($value in $ConfigValues){
    $value = $value.trim().replace(" ","").replace("/","").replace("_","").replace("IP","_IP")
    if($value -ne "FUTUREUSE"){
    $ConfigResult += @"
    {
        "title": "$value",
        "extractor_type": "split_and_index",
        "converters": [],
        "order": 0,
        "cursor_strategy": "copy",
        "source_field": "message",
        "target_field": "$value",
        "extractor_config": {
          "index": $Index,
          "split_by": ","
        },
        "condition_type": "string",
        "condition_value": ",CONFIG,"
      },

"@
    }
    $Index++
}

#Work out all the system strings
$SystemResult = ""
$Index = 1

foreach($value in $SystemValues){
    $value = $value.trim().replace(" ","").replace("/","").replace("_","").replace("IP","_IP")
    if($value -ne "FUTUREUSE"){
    $ConfigResult += @"
    {
        "title": "$value",
        "extractor_type": "split_and_index",
        "converters": [],
        "order": 0,
        "cursor_strategy": "copy",
        "source_field": "message",
        "target_field": "$value",
        "extractor_config": {
          "index": $Index,
          "split_by": ","
        },
        "condition_type": "string",
        "condition_value": ",SYSTEM,"
      },

"@
    }
    $Index++
}

#Mash everything together and kick it out as a file
$Start + $TrafficResult + $ThreatResult + $ConfigResult + $SystemResult + $End | Out-File $OutputPath