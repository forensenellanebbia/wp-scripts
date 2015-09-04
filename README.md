# wp78_parser.py
extracts the following artifacts:

- Account - Create Time
- Account - Default ID
- Account - Last Sync Success
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
- Last SIM IMSI
- OneDrive - DiskQuotaTotal and DiskQuotaRemaining
- OneDrive - list of uploaded files
- Shutdown Date Time
- SIM IMSI
- SMS (partial extraction)
- Wifi Adapter MAC Address
- Wireless SSIDs

# wp78_sms_xml.py
does the parsing of carved out SMS XML entries

# wp_appid.py
retrieves the AppName from an AppID
