# PANOSGraylogExtractorGenerator
Split &amp; Index extractor generator which will create the JSON needed to extract useful information from PAN-OS syslog and bring it into Graylog

# Note when using
These scripts don't kick out 'real' JSON - as such there is an extra comma where one shouldn't be at line max-4 on the generated output. Just remove that comma manually and you will be away! (one day I'll make a version that either kicks out real JSON or removes that comma for you :))
