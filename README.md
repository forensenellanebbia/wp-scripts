Scripts written in Python 2.7.8 and tested on Microsoft Windows.

Please read my blog post here:
http://forensenellanebbia.blogspot.it/2015/09/windows-phone-78-forensics.html

# wp78_parser.py
extracts the following artifacts from a forensic image:

- Account Create Time
- Account Default ID
- Account Last Sync Success
- Bluetooth connected devices
- Call Log (from pim.vol only - partial extraction)
- Contacts (from store.vol only - partial extraction)
- Device friendly name
- DHCP IP Address
- Email addresses
- GPS Last Known Position
- GPS Last Position Injected
- GPS Location Sync Start
- IMEI
- Internet Explorer - Typed URLs
- SIM IMSI and Last SIM IMSI
- OneDrive - DiskQuotaTotal and DiskQuotaRemaining
- OneDrive - list of uploaded files
- Shutdown Date Time
- SMS (the recipient's phone number is not decoded yet)
- Wifi Adapter MAC Address
- Wireless SSIDs

# wp78_sms_xml.py
does the parsing of carved out SMS XML entries

# wp_appid.py
retrieves AppNames from AppIDs
