#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Gabriele Zambelli (Twitter: @gazambelli)
# 
# WARNING: This program is provided "as-is"
# See http://forensenellanebbia.blogspot.it/ for further details.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Script        : Windows Phone - App Name finder
# Version       : v0.1
# Public Release: 2015-09-04

# Author        : Gabriele Zambelli
# Blog          : http://forensenellanebbia.blogspot.it
# Twitter       : @gazambelli

# Usage:
# wp_appid.py -i AppID
# wp_appid.py -f FILE


from BeautifulSoup import BeautifulSoup
import os
import re
import requests
import string
import sys
import urllib2


# function to retrieve AppName and AppURL from AppID
def solve_name(appid, userchoice):
    appurl      =""
    installedby = ["preinstalled", "user"] # status based on preinstalled apps found a NOKIA Lumia 800 phone
    by = installedby[0]
    appid       = appid.upper().rstrip('\n')
    if appid == '462D69A0-FAA3-4B1A-AACE-9C3652E0463D':
        appname = "Nokia Music"
    elif appid == '47621875-70B8-4755-B60C-435C0418E899':
        appname = "Contacts Transfer"
    elif appid == 'AB0D89CB-73A4-4FF8-93DD-91BEC9F855BD':
        appname = "Nokia Reading"
    elif appid == 'B5382DBF-0923-4195-B68B-F93B7EE76FE9':
        appname = "Nokia Drive"
    elif appid == 'BC4F319A-9A9A-DF11-A490-00237DE2DB9E':
        appname = "Adobe Reader"
    elif appid == 'C0109837-574E-469B-A08B-DCA621BDE3CA':
        appname = "Nokia Maps"
    elif appid == 'F2FABF6A-1F7D-4207-82E0-A4F3C0618F2D':
        appname = "NetworkSetting"
    elif appid == 'FD74FC03-8904-4631-950E-1CB2590E4212':
        appname = "STKApplication"
    elif appid == '93277D68-D147-45DB-A277-F67BBE8FFE7D':
        appname = "NokiaNPS.App"
    elif appid == '7C926679-58F4-4C18-B65F-0F9F21AE8290':
        appname = "Help How To"
    elif appid == '51F49C63-5966-4752-BB12-430455F911A8':
        appname = "Bluetooth Share"
        by = installedby[0] + "/" + installedby[1]
    elif appid == 'AD543082-80EC-45BB-AA02-FFE7F4182BA8':
        appname = "OneDrive"
        by = installedby[0] + "/" + installedby[1]        
    # https://msdn.microsoft.com/en-us/library/dn602089.aspx
    elif appid == '2C89D909-7691-4D36-A53D-B5FD425A0C19':
        appname = "Feedback Hub"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5601':
        appname = "Settings"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5603':
        appname = "Calculator"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA560A':
        appname = "Alarms"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5610':
        appname = "Messaging"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5611':
        appname = "Phone"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5612':
        appname = "Calendar"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5614':
        appname = "Mail"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5615':
        appname = "People"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA561B':
        appname = "One Note Mobile"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA561E':
        appname = "Office Hub"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA562D':
        appname = "Family Room"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5630':
        appname = "Music Videos"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5631':
        appname = "Camera"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5632':
        appname = "Photos"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5633':
        appname = "Store"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5634':
        appname = "Games"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5660':
        appname = "Internet Explorer"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5661':
        appname = "Search"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5683':
        appname = "Wallet"
    elif appid == '5B04B775-356B-4AA0-AAF8-6491FFEA5802':
        appname = "Kid Zone"
    elif appid == '892E3992-8909-4443-81E2-3D8281981975':
        appname = "Employee Apps"
    elif appid == '290CACFA-0F1C-4A75-8C27-60D796DBC26F':
        appname = "Viber"
        by = installedby[1]
    elif appid == '55A4097E-D65F-4A77-81A3-7FEC8BACDEDD':
        appname = "Nokia Creative Studio"
        by = installedby[0] + "/" + installedby[1]
    elif appid == 'B95840DC-A542-42A6-BEE4-7D1A12F62D2C':
        appname = "Network Setup"
        by = installedby[1]
    elif appid == 'DD91F5D5-9CF8-4D1D-8FBA-BEAA01FAFA47':
        appname = "Counters"
        by = installedby[1]
    else:
        hdr = {'User-Agent':'Mozilla/5.0'}
        url="http://windowsphone.com/s?appid="+appid
        req = urllib2.Request(url,headers=hdr)
        r = requests.get(url)
        try:
            soup = BeautifulSoup(urllib2.urlopen(req))
            appname = soup.title.string[:-18] # get rid of the string "- Microsoft Store"
            appname = filter(lambda x: x in string.printable, appname)
            appurl  = r.url
            by      = installedby[1]
        except:
            appname = "NOT FOUND"
            appurl  = appid
            by      = "unknown"

    # Fields: App Name | Installed by | App ID | URL

    if userchoice == '-i':
        print " " + appname + " (installed by: " + by + ")\n" + "\n " + appurl + "\n\n"
    if userchoice == '-f':
        print " " + appid + " ... " + appname.replace("Windows Apps","").replace("Windows Games","")
        return [appname, by, appid, appurl]
        

# main
appid_msg=" The AppID string must be written in the format:\n ########-####-####-####-############ (36 characters in total)"

def welcome():
    os.system("cls")
    print "\n *** Windows Phone - App Name finder (v0.1) ***\n"
    print "\n How to use ==> python wp_appid.py [option]\n\n"
    print "  -i AppID ... The AppID string must be written in the format:\n               ########-####-####-####-############\n               (36 characters in total)\n"
    print "\n  -f file  ... reads AppIDs from a text file and sends output to\n               a tab delimited CSV file\n"

# input check

if len(sys.argv) == 1:
    welcome()
else:
    userchoice = sys.argv[1]
    os.system("cls")
    if sys.argv[1]=='-i':
        if len(sys.argv[2])==36:
            print "\n This App ID corresponds to:\n"
            solve_name(sys.argv[2], userchoice)
            print "\n Done!\n\n"
        else:
            print "\n ERROR\n\n" + appid_msg
    elif sys.argv[1]=='-f':
        if os.path.exists(sys.argv[2]):
            print "\n *** Windows Phone - App Name finder (Preview Results) ***\n"
            print " [ Open the output file appid_output.csv when finished ]\n\n"
            if os.path.exists('appid_output.csv'):
                os.remove('appid_output.csv')
            with open('appid_output.csv','a') as w:
                w.write('App Name\tInstalled by\tApp ID\tURL\n')
                with open(sys.argv[2], 'r') as f:
                    for line in f:
                        if ":" not in line:
                            if len(line) == 36: # AppID must be 36 characters long
                                appname, by, appid, appurl = solve_name(line, userchoice)
                                w.write ("%s\t%s\t%s\t%s\n" % (appname, by, appid, appurl))
                            elif len(line) > 36:
                                filtered = filter(lambda x: x in string.printable, line)
                                find=re.findall(r'\b[0-9a-bA-Z\-]{36}\b', filtered)
                                if len(find) > 0:
                                    appname, by, appid, appurl = solve_name(find[0], userchoice)
                                    w.write ("%s\t%s\t%s\t%s\n" % (appname, by, appid, appurl))
                            else:
                                pass
            w.close()
            print "\n Done!\n\n"
        else:
            print "ERROR: wrong file name"
    else:
        welcome()
