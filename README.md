Windows Phone 7.8 - Mobile Forensics 

Scripts written in Python 2.7 and tested on Windows 7+.

Please read my blog posts here:
http://forensenellanebbia.blogspot.it/2015/09/windows-phone-78-forensics.html
http://forensenellanebbia.blogspot.it/2016/04/whatsapp-chat-parser-for-windows-phone.html

# wp78_parser.py
extracts the following artifacts from a forensic image:

- IMEI
- SIM IMSI and Last SIM IMSI
- Account Create Time
- Account Default ID
- Account Last Sync Success
- Contacts (from store.vol only - partial extraction)
- Call Log (from pim.vol only - partial extraction)
- SMS (the recipient's phone number is not decoded yet)
- Internet Explorer - Typed URLs
- Device friendly name
- Bluetooth connected devices
- Wifi Adapter MAC Address
- Wireless SSIDs
- DHCP IP Address
- Shutdown Date Time
- Email addresses
- OneDrive - DiskQuotaTotal and DiskQuotaRemaining
- OneDrive - list of uploaded files
- GPS Last Known Position
- GPS Last Position Injected
- GPS Location Sync Start

# wp78_sms_xml.py
does the parsing of carved out SMS XML entries

# wp_appid.py
retrieves AppNames from AppIDs

# wp78_wa.py
WhatsApp chat parser
Script tested against WhatsApp v2.11.670 (WhatsApp build released late Feb 2015)