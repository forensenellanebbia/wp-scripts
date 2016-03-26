#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Gabriele Zambelli (Twitter: @gazambelli)
# Blog  : http://forensenellanebbia.blogspot.it
#
# WARNING: This program is provided "as-is"
# See http://forensenellanebbia.blogspot.it/2015/09/windows-phone-78-forensics.html for further details.

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
# __                             __
# __ SCRIPT TESTED ON PYTHON 2.7 __
#
#
# Python script to parse the following artifacts from a Windows 7.8 phone:
#  - App IDs
#  - Account - Create Time
#  - Account - Default ID
#  - Account - Last Sync Success
#  - Bluetooth connected devices
#  - Call Log (from pim.vol only - partial extraction)
#  - Contacts (from store.vol only - partial extraction)
#  - Device friendly name
#  - DHCP IP Address
#  - Email addresses 
#  - GPS Last Known Position
#  - GPS Last Position Injected
#  - GPS Location Sync Start
#  - IMEI
#  - Internet Explorer - Typed URLs
#  - Last SIM IMSI
#  - OneDrive - DiskQuotaTotal and DiskQuotaRemaining
#  - OneDrive - list of uploaded files
#  - Shutdown Date Time
#  - SIM IMSI
#  - SMS (sent message decoding still lacks the recipient's phone number)
#  - Wifi Adapter MAC Address
#  - Wireless SSIDs
#
# You can run the script against: user.hv, system.hv, store.vol, pim.vol and image file


# Change history
# 2015-09-04 (v0.1) First public release
# 2016-03-20 (v0.2) Thanks to Vincent ECKERT for decoding the timestamp and the message type (SENT/RECEIVED) of SMS text messages
# 2016-03-26 (v0.3) improved unicode support + several small bugs fixed

# ***************************************************************************************************************************************************
# Welcome
# ***************************************************************************************************************************************************

from datetime import datetime,timedelta
import binascii
import codecs
import os
import re
import string
import struct
import sys
import time
import urllib

script_version = "0.3"

def welcome():
    os.system('cls')
    print "\n\n Windows Phone 7.8 - Artifacts Parser (v%s)\n\n" % script_version
    print " How to use ==> python wp78_parser.py [file] [options]\n\n"
    print " Important files to analyze are:\n store.vol, pim.vol, CommsBackup.xml, system.hv, user.hv\n"
    
    print "   -a   ...... account information (Default ID, Account Create Time,\n               Last Sync Success)"
    print "   -d   ...... device artifacts (IMEI, WiFi MAC Address,\n               Device friendly name, Last Shutdown, SIM IMSI)"
    print "   -g   ...... GPS (LastKnownLocation, LastPosInjected, LocationSyncStart)"
    print "   -h   ...... Internet Explorer History (Typed URLs)"
    print "   -ip  ...... DHCP IP Address"
    print "   -o   ...... OneDrive artifacts (DiskQuotaUse, Files Uploaded)"
    print "   -p   ...... Personal information (contacts, Call Log, E-mail addresses)"
    print "   -s   ...... SMS messages"
    print "   -w   ...... Wireless connections (Bluetooth, Wireless SSIDs)"
    print "   -i   ...... AppID"
    print "   -all ...... Extract all artifacts (it can take up to 2h 30min\n               against a forensic image)\n"
    print "\n Except for SMS messages, all output goes to STDOUT.\n Use redirection to output to a file.\n"

if len(sys.argv) > 2:
    if os.path.exists(sys.argv[1]) == True:
        pass
    else:
        welcome()
        sys.exit()
else:
    welcome()
    sys.exit()

fb = open(sys.argv[1], "rb")


# ***************************************************************************************************************************************************
# FUNCTIONS
# ***************************************************************************************************************************************************

# -- BEGIN -- From https://github.com/cheeky4n6monkey/4n6-scripts/blob/master/wp8-callhistory.py -- BEGIN --

# Find all indices of the "pattern" regular expression in a given string (using regex)
# Where pattern is a compiled Python re pattern object (ie the output of "re.compile")

CHUNK_SIZE = 50000000 #50MB   2000000000 # max value of CHUNK_SIZE + DELTA is 2147483647 (C long limit with Python 2)
DELTA = 1000 # read this extra bit to catch any hits crossing chunk boundaries. Should be AT LEAST max size of record being searched for.

def regsearch(bigstring, pattern, listindex=[]):
    hitsit = pattern.finditer(bigstring)
    for it in hitsit:
        # iterators only last for one shot so we capture the offsets to a list
        listindex.append(it.start())
    return listindex

# Searches chunks of a file (using RE) and returns file offsets of any hits.
# Intended for searching of large files where we cant read the whole thing into memory
# This function calls the "regsearch" search method
def sliceNsearchRE(fd, chunksize, delta, term):
    final_hitlist = [] # list of file offsets which contain the search term
    pattern = re.compile(term, re.DOTALL) # should only really call this once at start, if same substring.
    stats = os.fstat(fd.fileno())
    #print("sliceNsearchRE Input file " + filename + " is " + str(stats.st_size) + " bytes\n")
    begin_chunk = 0

    # Handle if filesize is less than CHUNK_SIZE (eg Phone file instead of image.bin)
    # Should be able to read whole file in 1 chunk 
    if (chunksize >= stats.st_size):
        fd.seek(begin_chunk)
        raw = fd.read()
        final_hitlist = regsearch(raw, pattern, [])
        #print(str(len(final_hitlist)) + " hits found in 1 chunk for " + str(term))
    else:
        # Filesize is greater than 1 chunk, need to loop thru
        while ((begin_chunk + chunksize) <= stats.st_size) :
            chunk_size_to_read = chunksize + delta
            if ((chunk_size_to_read + begin_chunk) > stats.st_size):
                chunk_size_to_read = stats.st_size - begin_chunk
            #print("seeking " + str(begin_chunk) + " with size = " + str(chunk_size_to_read))
            fd.seek(begin_chunk)
            rawchunk = fd.read(chunk_size_to_read)
            subhits = regsearch(rawchunk, pattern, [])
            #print(str(len(subhits)) + " hits found at " + str(subhits))
            # Items in subhits will be offsets relative to the start of the rawchunk (not relative to the file)
            # Need to adjust offsets ...
            for hit in subhits :
                if (hit < chunksize) :
                    final_hitlist.append(begin_chunk + hit)
                    #print("adding " + str(begin_chunk + hit) + " to list")
                elif (hit >= chunksize) :
                    #print("ignoring " + str(begin_chunk + hit) + " to list")
                    break # don't care if we get here because hit should be processed in next chunk
                    # subhits can start at index 0 so possible hit offsets are 0 to chunksize-1 inclusive
            begin_chunk += chunksize
    #print("final_hitlist = " + str(final_hitlist))
    return(final_hitlist)

# -- END -- From https://github.com/cheeky4n6monkey/4n6-scripts/blob/master/wp8-callhistory.py -- END --


def f_search_ip(ip2search):
    ip = re.findall( r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', ip2search)
    return ip 


def f_dhcp(off1,off2):
    #find DhcpSubnetMask
    fb.seek(off1+off2+28)
    raw_ip=fb.read(30).split("\x00\x00")
    try:
        raw_ip=raw_ip[0].replace("\x00","")
        b = "DhcpSubnetMask    : " + str(f_search_ip(raw_ip)[0]) #DhcpSubnetMask
    except:
        b = "DhcpSubnetMask    : Not found" #DhcpSubnetMask
    return b


def f_getaway(off1,off2):
    fb.seek(off1+off2+36)
    raw_ip=fb.read(30).split("\x00\x00")
    try:
        raw_ip=raw_ip[0].replace("\x00","")
        c = "DhcpDefaultGateway: " + str(f_search_ip(raw_ip)[0]) #DhcpDefaultGateway
    except:
        c = "DhcpDefaultGateway: Not found" #DhcpDefaultGateway
    return c


def f_dns(off1,off2):
    fb.seek(off1+off2+14)
    raw_ip=fb.read(30).split("\x00\x00")
    try:
        raw_ip=raw_ip[0].replace("\x00","")
        d = "DhcpDNS           : " + str(f_search_ip(raw_ip)[0]) #DhcpDNS
    except:
        d = "DhcpDNS           : Not found" #DhcpDNS
    return d


def f_lease(off1,off2):
    fb.seek(off1+off2+30)
    data=binascii.hexlify(fb.read(8))
    #invert byte order for conversion
    #http://stackoverflow.com/questions/4869769/convert-64-bit-windows-date-time-in-python
    dt=data[14]+data[15]+data[12]+data[13]+data[10]+data[11]+data[8]+data[9]+data[6]+data[7]+data[4]+data[5]+data[2]+data[3]+data[0]+data[1]
    us = int(dt,16) / 10
    try:
        conversion= datetime(1601,1,1) + timedelta(microseconds=us)
        e = "LeaseObtainedHigh : " + str(conversion) + " (UTC)"
    except:
        e = "LeaseObtainedHigh : Not found"
    return e


def f_timestamp_filetime(data):
    #invert byte order for conversion
    dt=data[14]+data[15]+data[12]+data[13]+data[10]+data[11]+data[8]+data[9]+data[6]+data[7]+data[4]+data[5]+data[2]+data[3]+data[0]+data[1]
    us = int(dt,16) / 10
    try:
        conversion= datetime(1601,1,1) + timedelta(microseconds=us)
    except:
        conversion = "not found"
    return conversion


def f_timestamp_tick(tick):
    ticks = int(tick[-18:])
    # http://stackoverflow.com/questions/3875806/how-does-one-convert-a-net-tick-to-a-python-datetime
    dmoc  = datetime(1, 1, 1) + timedelta(microseconds = ticks/10)
    return dmoc #dateModifiedOnClient

# ***************************************************************************************************************************************************
# SIGNATURES
# ***************************************************************************************************************************************************

#device
sig_imei             = "\x04\x49\x4D\x45\x49\x04\x00\x0F"
sig_friendlyname     = "\x0c\x00\x46\x00\x72\x00\x69\x00\x65\x00\x6E\x00\x64\x00\x6C\x00\x79\x00\x4E\x00\x61\x00\x6D\x00\x65\x00" #..F.r.i.e.n.d.l.y.N.a.m.e.
sig_sim_imsi         = "\x07\x02\x53\x00\x69\x00\x6D\x00\x49\x00\x6D\x00\x73\x00\x69\x00"
sig_last_sim_imsi    = "\x0B\x00\x4C\x00\x61\x00\x73\x00\x74\x00\x53\x00\x69\x00\x6D\x00\x49\x00\x6D\x00\x73\x00\x69"
sig_last_shutdown    = "\x4C\x00\x61\x00\x73\x00\x74\x00\x53\x00\x68\x00\x75\x00\x74\x00\x64\x00\x6F\x00\x77\x00\x6E\x00\x44\x00\x61\x00\x74\x00\x65\x00\x54\x00\x69\x00\x6D\x00\x65"
sig_wifi_adapter_mac = "\x41\x00\x64\x00\x61\x00\x70\x00\x74\x00\x65\x00\x72\x00\x4D\x00\x61\x00\x63\x00\x41\x00\x64\x00\x64\x00\x72\x00\x65\x00\x73\x00\x73\x00"

#dhcp
sig_dhcpipaddress      = "\x44\x00\x68\x00\x63\x00\x70\x00\x49\x00\x50\x00\x41\x00\x64\x00\x64\x00\x72\x00\x65\x00\x73\x00\x73\x00"
sig_dhcpsubnetmask     = "\x44\x00\x68\x00\x63\x00\x70\x00\x53\x00\x75\x00\x62\x00\x6E\x00\x65\x00\x74\x00\x4D\x00\x61\x00\x73\x00\x6B\x00"
sig_dhcpdefaultgetaway = "\x44\x00\x68\x00\x63\x00\x70\x00\x44\x00\x65\x00\x66\x00\x61\x00\x75\x00\x6C\x00\x74\x00\x47\x00\x61\x00\x74\x00\x65\x00\x77\x00\x61\x00\x79\x00"
sig_dhcpserver         = "\x44\x00\x68\x00\x63\x00\x70\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
sig_dhcpdns            = "\x44\x00\x68\x00\x63\x00\x70\x00\x44\x00\x4E\x00\x53\x00"
sig_gprsaddress        = "\x47\x00\x50\x00\x52\x00\x53\x00\x41\x00\x64\x00\x64\x00\x72\x00\x65\x00\x73\x00\x73\x00"
sig_lease_obtained_hi  = "\x4C\x00\x65\x00\x61\x00\x73\x00\x65\x00\x4F\x00\x62\x00\x74\x00\x61\x00\x69\x00\x6E\x00\x65\x00\x64\x00\x48\x00\x69\x00"

#gps
sig_lastposinjected   = "\x4C\x00\x61\x00\x73\x00\x74\x00\x50\x00\x6F\x00\x73\x00\x49\x00\x6E\x00\x6A\x00\x65\x00\x63\x00\x74\x00\x65\x00\x64\x00"
sig_lastknownlocation = "\x4C\x00\x61\x00\x73\x00\x74\x00\x4B\x00\x6E\x00\x6F\x00\x77\x00\x6E\x00\x4C\x00\x6F\x00\x63\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E\x00"
sig_locationsyncstart = "\x4C\x00\x6F\x00\x63\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x53\x00\x79\x00\x6E\x00\x63\x00\x53\x00\x74\x00\x61\x00\x72\x00\x74\x00"

#Bluetooth
sig_bt_name            = "\x04\x00\x6E\x00\x61\x00\x6D\x00\x65\x00" #n.a.m.e.
sig_bt_lastconnecttime = "\x4C\x00\x61\x00\x73\x00\x74\x00\x43\x00\x6F\x00\x6E\x00\x6E\x00\x65\x00\x63\x00\x74\x00\x54\x00\x69\x00\x6D\x00\x65\x00" # L.a.s.t.C.o.n.n.e.c.t.T.i.m.e.
sig_bt_class           = "\x63\x00\x6C\x00\x61\x00\x73\x00\x73\x00" #c.l.a.s.s.

#URL
sig_url_lastvisited = "\x4C\x00\x61\x00\x73\x00\x74\x00\x56\x00\x69\x00\x73\x00\x69\x00\x74\x00\x65\x00\x64\x00"
sig_url_title       = "\x54\x00\x69\x00\x74\x00\x6C\x00\x65\x00"

#OneDrive livefilestore.com
sig_od_download              = "\x22\x75\x72\x6C\x73\x22\x3A\x7B\x22\x64\x6F\x77\x6E\x6C\x6F\x61\x64\x22\x3A"                          # "urls":{"download":
sig_od_url                   = "\x22\x75\x72\x6C\x22\x3A\x22\x2E\x6C\x69\x76\x65\x66\x69\x6C\x65\x73\x74\x6F\x72\x65\x2E\x63\x6F\x6D"  # "url":".livefilestore.com
sig_od_datemodifiedonclient  = "\x2C\x22\x64\x61\x74\x65\x4D\x6F\x64\x69\x66\x69\x65\x64\x4F\x6E\x43\x6C\x69\x65\x6E\x74\x22\x3A"      # ,"dateModifiedOnClient":
sig_od_displayquotaremaining = "\x22\x64\x69\x73\x70\x6C\x61\x79\x51\x75\x6F\x74\x61\x52\x65\x6D\x61\x69\x6E\x69\x6E\x67\x22\x3A"      # "displayQuotaRemaining":
sig_od_displayquotatotal     = "\x22\x64\x69\x73\x70\x6C\x61\x79\x51\x75\x6F\x74\x61\x54\x6F\x74\x61\x6C\x22\x3A\x22"                  # "displayQuotaTotal":"
sig_od_displayquotaused      = "\x22\x64\x69\x73\x70\x6C\x61\x79\x51\x75\x6F\x74\x61\x55\x73\x65\x64\x22\x3A\x22 "                     # "displayQuotaUsed":"

#account
sig_account_defaultid  ="\x44\x00\x65\x00\x66\x00\x61\x00\x75\x00\x6C\x00\x74\x00\x49\x00\x44\x00"
sig_account_create_time       = "\x41\x00\x63\x00\x63\x00\x6F\x00\x75\x00\x6E\x00\x74\x00\x43\x00\x72\x00\x65\x00\x61\x00\x74\x00\x65\x00\x54\x00\x69\x00\x6D\x00\x65\x00"
sig_account_last_sync_success = "\x4C\x00\x61\x00\x73\x00\x74\x00\x53\x00\x79\x00\x6E\x00\x63\x00\x53\x00\x75\x00\x63\x00\x63\x00\x65\x00\x73\x00\x73\x00"

#smtp
sig_smtp_email_address = "\x80\x53\x4D\x54\x50\x00"

#wifi
sig_ssid_start = "\x3C\x2F\x68\x65\x78\x3E\x0D\x0A\x09\x09\x09\x3C\x6E\x61\x6D\x65\x3E"     # </hex>.....<name>
sig_ssid_end   = "\x3C\x2F\x6E\x61\x6D\x65\x3E\x0D\x0A\x09\x09\x3C\x2F\x53\x53\x49\x44\x3E" # </name>....</SSID>

#SMS
sig_sms_pre1    = "\x40\x00\x07\x00\x0A"                         # hex sequence before SMS header
sig_sms_pre2    = "\x40\x00\x07\x00\xFF"                         # hex sequence before SMS header
sig_sms_pre3    = "\x38\x00\x07\x00\x0A"                         # hex sequence before SMS header
sig_sms_pre4    = "\x40\x00\x07\x00\x0B"                         # hex sequence before SMS header
sig_sms_header1 = "\x49\x50\x4D\x2E\x53\x4D\x53\x74"             # (SMS HEADER) IPM.SMSt
sig_sms_header2 = "\x49\x50\x4D\x2E\x53\x4D\x53\x74\x65\x78\x74" # (SMS HEADER) IPM.SMStext
sig_sms_footer1 = "\x00\x00\x53\x4D\x53\x00\x00"                 # (SMS FOOTER) ..SMS..
sig_sms_footer2 = "\x00\x00\x53\x4D\x53\x00\xFF"                 # (SMS FOOTER) ..SMS..
sig_sms_footer3 = "\xFF\x0F\x53\x4D\x53\x00\x00"                 # (SMS FOOTER) ÿ.SMS..

#APPID
sig_appid = "\x3D\x00\x22\x00\x61\x00\x70\x00\x70\x00\x3A\x00\x2F\x00\x2F\x00" # ="app://


# ***************************************************************************************************************************************************
# App ID
# ***************************************************************************************************************************************************

def af_appid():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_appid)
    appid_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+16)
        raw_text=fb.read(72).replace("\x00","")
        find = re.findall(r'[A-F0-9]{8}\-[A-F0-9]{4}\-[A-F0-9]{4}\-[A-F0-9]{4}\-[A-F0-9]{12}', raw_text)
        if len(find)>0:
            appid_list.append(find[0])
                
    appid_list=set(appid_list)
    appid_list=sorted(list(appid_list))
    
    if len(appid_list) > 0:
        print "\n********************************************\n AppIDs (%s)\n\n (Use the script wp_appid.py to get AppNames\n from the following AppIDs)\n********************************************\n" % str(len(appid_list))
        for i in appid_list:
            print i


       
# ***************************************************************************************************************************************************
# Friendly name (system.hv)
# ***************************************************************************************************************************************************

def af_friendly_name():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_friendlyname)
    friendlyname_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+26)
        raw_text=fb.read(32).replace("\x00","")
        find = re.findall( r'[ 0-9a-zA-Z_-]{2,21}', raw_text)
        if len(find)>0:
            if "proxy" in find[0].lower():
                pass
            else:
                friendlyname_list.append(find[0])
                
    friendlyname_list=sorted(set(friendlyname_list))
    
    if len(friendlyname_list) > 0:
        print "\n********************************************\n Device friendly name (%s)\n********************************************\n" % str(len(friendlyname_list))
        for i in friendlyname_list:
            print i
        

# ***************************************************************************************************************************************************
# IMEI
# *****************************************************************************************************************************************************

def af_imei():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_imei)
    imei_list=[]
    
    for hit in hits:
        fb.seek(hit+8)
        raw_text=fb.read(17)
        find = re.findall( r'[0-9]{15,17}', raw_text)
        try:
            if len(find)>0:
                imei_list.append(find[0])
        except:
            pass
                
    imei_list=sorted(set(imei_list))
    
    if len(imei_list) > 0:
        print "\n********************************************\n IMEI \n********************************************\n"
        for i in imei_list:
            print i


# ***************************************************************************************************************************************************
# DHCP (system.hv)
# *****************************************************************************************************************************************************

# offsets from DhcpIpAddress
#
# length of strings: dhcipaddress (26), sig_dhcpsubnetmask (28), DhcpDefaultGateway (36), sig_dhcpdns (14), LeaseObtainedHigh (30)

def af_dhcp():
    off_dhcpsubnetMask    = [76,80,84]
    off_dhcpdefaultgetaway= [160,164,168,236,240,244,248]
    off_dhcpdns           = [248,252,256,320,324,328,336,340]
    off_leaseObtainedHigh = [372,376,416,452,464,468,480,488,496,716]
    
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_dhcpipaddress)
    
    hits_smask      = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_dhcpsubnetmask)
    hits_dhcpserver = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_dhcpserver)
    hits_getaway    = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_dhcpdefaultgetaway)
    hits_dns        = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_dhcpdns)
    hits_lease      = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_lease_obtained_hi)
    
    dhcp_temp=[]
    for hit in hits:
        nf = 0 #counter to keep track of not found values
        #find DhcpIPAddress
        fb.seek(hit+26)
        try:
            raw_ip=fb.read(30).replace("\x00","")
            a = "DhcpIPAddress     : " + f_search_ip(raw_ip)[0] #print IP Address
        except:
            pass
    
        #find DhcpSubnetMask
        if off_dhcpsubnetMask[0]+hit in hits_smask:
            b=f_dhcp(hit,off_dhcpsubnetMask[0])
        elif off_dhcpsubnetMask[1]+hit in hits_smask:
            b=f_dhcp(hit,off_dhcpsubnetMask[1])
        elif off_dhcpsubnetMask[2]+hit in hits_smask:
            b=f_dhcp(hit,off_dhcpsubnetMask[2])
        else:
            b = "DhcpSubnetMask    : Not found"
            nf += 1
    
        #find DhcpGetaway
        if off_dhcpdefaultgetaway[0]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[0])
        elif off_dhcpdefaultgetaway[1]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[1])
        elif off_dhcpdefaultgetaway[2]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[2])
        elif off_dhcpdefaultgetaway[3]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[3])
        elif off_dhcpdefaultgetaway[4]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[4])
        elif off_dhcpdefaultgetaway[5]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[5])
        elif off_dhcpdefaultgetaway[6]+hit in hits_getaway:
            c = f_getaway(hit, off_dhcpdefaultgetaway[6]) 
        else:
            c = "DhcpDefaultGateway: Not found"
            nf += 1   
    
        #find DhcpDns
        if off_dhcpdns[0]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[0])
        elif off_dhcpdns[1]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[1])
        elif off_dhcpdns[2]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[2])
        elif off_dhcpdns[3]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[3])
        elif off_dhcpdns[4]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[4])
        elif off_dhcpdns[5]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[5])
        elif off_dhcpdns[6]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[6])
        elif off_dhcpdns[7]+hit in hits_dns:
            d = f_dns(hit, off_dhcpdns[7])
        else:
            d = "DhcpDNS           : Not found"
            nf += 1
        
        #find DhcpLease
        if off_leaseObtainedHigh[0]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[0])
        elif off_leaseObtainedHigh[1]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[1])
        elif off_leaseObtainedHigh[2]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[2])
        elif off_leaseObtainedHigh[3]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[3])
        elif off_leaseObtainedHigh[4]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[4])
        elif off_leaseObtainedHigh[5]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[5])
        elif off_leaseObtainedHigh[6]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[6])
        elif off_leaseObtainedHigh[7]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[7])
        elif off_leaseObtainedHigh[8]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[8])
        elif off_leaseObtainedHigh[9]+hit in hits_lease:
            e = f_lease(hit, off_leaseObtainedHigh[9])
        else:
            e = "LeaseObtainedHigh : Not found"
            nf += 1
    
        f = a + ";" + b + ";" + c + ";" + d + ";" + e
        if nf <= 3: #skip DhcpIpAddresses with 4 values not found 
            dhcp_temp.append(f)
                        
    
    dhcp_final=[]
    
    for i in dhcp_temp:
        pos=i.rfind(";")
        new = i[-(len(i)-pos)+1:] + ";" + i[:pos].strip() #put timestamp in front to sort later by timestamp
        dhcp_final.append(new)
    
    dhcp_final=set(dhcp_final)
    dhcp_final=sorted(list(dhcp_final))
    
    if len(dhcp_final)>0:
        print "\n********************************************\n DHCP (%s) \n********************************************" % str(len(dhcp_final)) 
    
    for i in dhcp_final:
        pos=i.find(";")
        new = i[-(len(i)-pos)+1:] + ";" + i[:pos] #put timestamp back to the original position
        print "\n" + new.replace(";","\n")
    
    dhcpserver_list=[]
    for hit in hits_dhcpserver:
        fb.seek(hit+20)
        raw_ip=fb.read(30).replace("\x00","")
        try:
            dhcpserver_list.append(f_search_ip(raw_ip)[0]) #print IP Address
        except:
            pass
        
    dhcpserver_list = set(dhcpserver_list)
    dhcpserver_list = sorted(list(dhcpserver_list))
    
    if len(dhcpserver_list)>0:
        print "\n********************************************\n DHCP Server (%s) \n********************************************" % str(len(dhcpserver_list))
        for i in dhcpserver_list:
            print i

# ****************************************************************************************************************************************************
# Wi-Fi MAC Address (system.hv)
# ****************************************************************************************************************************************************

def af_wifi_adapter_mac():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_wifi_adapter_mac)
    
    if len(hits) > 0:
        fb.seek(hits[0]+34)
        print "\n********************************************\n Wi-Fi MAC address\n********************************************\n"
        print binascii.hexlify(fb.read(6))


# ****************************************************************************************************************************************************
# SIM IMSI (15 digit long number) (system.hv)
#*****************************************************************************************************************************************************

def af_sim_imsi():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sim_imsi)
    simimsi_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+2+14)
        simimsi_list.append(fb.read(30).replace("\x00",""))
    
    simimsi_list=sorted(set(simimsi_list))
    
    if len(simimsi_list)>0:
        print "\n********************************************\n SIM - IMSI (%s)\n********************************************\n" % str(len(simimsi_list))
        for i in simimsi_list:
            print i


# ***************************************************************************************************************************************************
# Last SIM IMSI (system.hv)
#*****************************************************************************************************************************************************

def af_last_sim_imsi():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_last_sim_imsi)
    lastsimimsi_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+2+22)
        raw_data = fb.read(30).replace("\x00","")
        find = re.findall( r'[0-9]{15,16}', raw_data)
        if find:
            lastsimimsi_list.append(find[0])
        else:
            pass #skipped false positive
        
    lastsimimsi_list=sorted(set(lastsimimsi_list))
    
    if len(lastsimimsi_list) > 0:
        print "\n********************************************\n SIM - Last SIM IMSI (%s) \n********************************************\n" % str(len(lastsimimsi_list))
        for i in lastsimimsi_list:
            print i

# ***************************************************************************************************************************************************
# Last Shutdown Date Time (system.hv)
# ***************************************************************************************************************************************************

def af_last_shutdown():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_last_shutdown)
    timestamp = []
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+40)
        data=binascii.hexlify(fb.read(8))
        conversion=f_timestamp_filetime(data)
        if str(conversion).startswith('20'):
            timestamp.append(conversion)
    
    timestamp = sorted(set(timestamp))
    
    if len(timestamp)>0:
        print "\n********************************************\n Device - Last shutdown date time (UTC) (%s)\n********************************************\n" % str(len(timestamp))
        for i in timestamp:
            print i

   
# ****************************************************************************************************************************************************   
# GPRS IP Address in unallocated space (system.hv)
# ****************************************************************************************************************************************************

def af_gprs_ipaddress():
    temp = []
    
    if 'system.hv' not in sys.argv[1]:
        hits_gprsaddress = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_gprsaddress)
        for hit in hits_gprsaddress:
            fb.seek(hit+22)
            raw_ip=fb.read(30).replace("\x00","")
            find = f_search_ip(raw_ip) #print GPRS IP Address
            try:
                temp.append(find[0])
            except:
                pass
        if len(temp)>0:
            temp=set(temp)
            temp=sorted(list(temp))
            print "\n********************************************\n GPRS Address (%s)\n********************************************" % str(len(temp))
            for i in temp:
                print i

# ***************************************************************************************************************************************************
# GPS: LastPosInjected - coordinates reported by geolocation apps (system.hv)
# ***************************************************************************************************************************************************

def af_gps_lastposinjected():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_lastposinjected)
    
    lastposinjected_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+30)
        raw_text=fb.read(62).replace("\x00","")
        find = re.findall( r'[-]?[0-9]{1,3}\.[0-9]{6},[-]?[0-9]{1,3}\.[0-9]{6}', raw_text) #find decimal coordinates
        if find:
            lastposinjected_list.append(find[0])
        else:
            pass #skip false positive
    
    lastposinjected_list=sorted(set(lastposinjected_list))
    
    if len(lastposinjected_list) > 0:
        print "\n********************************************\n GPS - Last Position Injected (%s)\n********************************************\n" % str(len(lastposinjected_list))
        for i in lastposinjected_list:
            print i

        
# ***************************************************************************************************************************************************
# GPS: LastKnownLocation (system.hv)
# ***************************************************************************************************************************************************

def af_gps_last_known_location():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_lastknownlocation)
    lastknownlocation_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+34)
        raw_text=fb.read(100).replace("\x00","")
        find = re.findall( r'[0-9Z: \-()]{23}[-]?[0-9]{1,3}\.[0-9]{6},[-]?[0-9]{1,3}\.[0-9]{6}', raw_text)
        if find:
            lastknownlocation_list.append(find[0])
        else:
            pass #skipped false positive
        
    if len(lastknownlocation_list) > 0:
        print "\n****************************************\n GPS - Last Known Location (%s)\n****************************************\n" % str(len(lastknownlocation_list))
        for i in lastknownlocation_list:
            print i

# **************************************************************************************************************************************************
# GPS: Location Sync Start (system.hv)
# **************************************************************************************************************************************************

def af_gps_location_syncstart():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_locationsyncstart)
    locationsyncstart_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+34)
        raw_text=fb.read(32).replace("\x00","")
        raw_text=raw_text[:4] + "-" + raw_text[4:6] + "-" + raw_text[6:8] + " " + raw_text[9:11] + ":" + raw_text[11:13] + ":" + raw_text[13:16]
        try:
            if '20' in raw_text:
                locationsyncstart_list.append(raw_text)
        except:
            pass
        
    locationsyncstart_list = set(locationsyncstart_list)
    locationsyncstart_list = sorted(list(locationsyncstart_list))
    
    if len(locationsyncstart_list) > 0:
        print "\n****************************************\n GPS - Location Sync Start (UTC) (%s)\n****************************************\n" % str(len(locationsyncstart_list))
        for i in locationsyncstart_list:
            print i


# **************************************************************************************************************************************************
# Bluetooth connected devices (system.hv)
# ***************************************************************************************************************************************************

# Keytype | ...macaddress ... | name | class | LastConnectTime

def af_bluetooth():
    hits_bt_name            = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_bt_name)
    hits_bt_class           = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_bt_class)
    hits_bt_lastconnecttime = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_bt_lastconnecttime)
    
    temp = []
    for btclass in hits_bt_class:
        if btclass+84 in hits_bt_lastconnecttime:
            if btclass-54 in hits_bt_name: #from "class" go back to find "name"
                fb.seek(btclass+84+30) #read timestamp
                data=binascii.hexlify(fb.read(8))
                conversion=f_timestamp_filetime(data)
                a = "\nLastConnectTime: " + str(conversion) + " (UTC)"
                fb.seek(btclass-54+10) # 10 is the length of the string "..name" in unicode
                raw_text=fb.read(28).split("\x00\x00") #bluetooth device name
                raw_text=raw_text[0].replace("\x00","") #bluetooth device name
                find = re.findall( r'[0-9a-zA-Z -_#!?:]*', raw_text)
                b = "Device name    : " + find[0]
                fb.seek(btclass-98) #macaddress
                raw_text=fb.read(24).replace("\x00","")
                c = "MAC Address    : " + raw_text
                temp.append(a + "\t" + b + "\t" + c)
    temp = set(temp)
    temp = sorted(list(temp))

    if len(temp) > 0:
        print "\n****************************************\n Bluetooth - connected devices\n****************************************"
        for i in temp:
            print i.replace("\t","\n")


# *************************************************************************************************************************************************
# Internet Explorer - Typed URLs (user.hv)
# (item sequence in hex: URL, LastVisited, Title)
# *************************************************************************************************************************************************

def af_ie_typed_urls():
    hits_lastvisited = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_url_lastvisited)
    hits_title       = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_url_title)
    
    temp=[]
    for hit in hits_lastvisited:
            fb.seek(hit-240) #from LastVisited go back and look for URLs nearby
            raw_text=fb.read(240).replace("\x00","").lower()
            find = re.findall(r'(?:https|http):[0-9a-zA-Z:/\.\-\=%?&+]*', raw_text) #look for URLs
            if len(find) == 0:
                pass
            else:
                fb.seek(hit+22) #lastvisited
                data=binascii.hexlify(fb.read(8))
                conversion=f_timestamp_filetime(data)
                a = urllib.unquote(find[0]) #URL found, decode escaped characters in URL
                b ="LastVisited: " + str(conversion) + " (UTC)"
                if hit+96 in hits_title:
                    fb.seek(hit+96+10)
                    raw_text=fb.read(200).replace("\x00","")
                    title_grab=re.findall(r'[0-9a-zA-Z:/, -]*', raw_text)
                    c = "Title      : " + title_grab[0]
                    d = b + ";" + a + ";" + c  #LastVisited, URL, Title
                    temp.append(d)
                elif hit+144 in hits_title:
                    fb.seek(hit+144+10)
                    raw_text=fb.read(200).replace("\x00","")
                    title_grab=re.findall(r'[0-9a-zA-Z:/, -]*', raw_text)
                    c = "Title      : " + title_grab[0]
                    d = b + ";" + a + ";" + c
                    temp.append(d)
                else:
                    d = b + ";" + a
                    temp.append(d)
                
    temp=set(temp)
    temp=sorted(list(temp))
    
    if len(temp)>0:
        print "\n********************************************\n Internet Explorer (Typed URLs) (%s)\n********************************************\n" % str(len(temp))
        for i in temp:
            i=i.replace(";","\n")
            print "URL        : " + i[46:]  #print URL, Title
            print i[:46]                    #print LastVisited
    

# ***************************************************************************************************************************************************    
# Account (user.hv)
# ***************************************************************************************************************************************************

def af_account():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_account_defaultid) #defaultid in user.hv is the current Microsoft account set up on the mobile device
    defaultid_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+18)
        raw_text=fb.read(72).replace("\x00","")
        find = re.findall( r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b', raw_text) #grep e-mail addresses after DefaultID
        if len(find)>0:
                defaultid_list.append(find[0])
        else:
            pass
      
    defaultid_list=set(defaultid_list)
    defaultid_list=sorted(list(defaultid_list))
    
    if len(defaultid_list) > 0:
        print "\n****************************************\n Current/Previous account (%s) \n****************************************" % str(len(defaultid_list))
        if 'user.hv' in sys.argv[1]:
            print "\nDefault ID (current account)"
        else:
            print "\nDefault ID (current/previous account)"
            for i in defaultid_list :
                print i
    
# **************************************************************************************************************************************************    
# Account Create Time = when the account was set up on the phone (user.hv)
# Account Last Sync Success - last time the account was synced (unallocated space)
# **************************************************************************************************************************************************

def af_account_create_time():
    hits  = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_account_create_time)
    hits2 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_account_last_sync_success)
    
    temp=[]
    
    for hit in hits: #for each AccountCreateTime
        fb.seek(hit)
        fb.seek(hit+34)
        data=binascii.hexlify(fb.read(8)) #read timestamp
        conversion=f_timestamp_filetime(data)
        if 'user.hv' in sys.argv[1]:
            fb.seek(hit-1364+10) #email 1364 - email field 10
            raw_text=fb.read(100).replace("\x00","")
            find = re.findall( r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}', raw_text) #grep email address
            if len(find)>0:
                print "\nUser               : " + find[0]
                print "Account Create Time: " + str(conversion) + " (UTC)"
                for i in hits2:
                    diff=i-hit
                    if diff<20000:
                        fb.seek(i+30)
                        data=binascii.hexlify(fb.read(8)) #reads timestamp
                        conversion=f_timestamp_filetime(data)
                        print "Last Sync Success  : " + str(conversion) + " (UTC)" #usually found in user.hv
        else:
            fb.seek(hit-412+10) #email (412), email field length (10)
            raw_text=fb.read(100).replace("\x00","")
            find = re.findall( r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}', raw_text)
            if len(find)>0:
                a = "\nUser               : " + find[0]
                b=  "Account Create Time: " + str(conversion) + " (UTC)"
                c = a + ";" + b
                temp.append(c)
    
    #dedupe User / AccountCreateTime found in the unallocated space
    temp=set(temp)
    temp=sorted(list(temp))
    for i in temp:
        print i.replace(";","\n")

    temp=[]
    
    if 'user.hv' not in sys.argv[1]:
        for i in hits2:
            fb.seek(i+30)
            data=binascii.hexlify(fb.read(8)) #read timestamp
            conversion=f_timestamp_filetime(data)
            a = "Last Sync Success: " + str(conversion) + " (UTC)"
            temp.append(a)
        if len(temp)>0:
            #dedupe LastSyncSuccess hits
            temp=set(temp)
            temp=sorted(list(temp))
            print "\n\nLastSyncSuccess\n(correlate these dates with the AccountCreateTime of each account)\n"
            for i in temp:
                print i 


# **************************************************************************************************************************************************
# OneDrive - Disk Quota and Usage
# **************************************************************************************************************************************************

# dateModifiedOnClient | DisplayQuotaRemaining | DisplayQuotaTotal | DisplayQuotaUsed

def af_onedrive_disk_quota():
    od_quota_list = []
    
    hits_dqr  = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_od_displayquotaremaining)
    
    if len(hits_dqr) > 0:
        for hit_dqr in hits_dqr:
            dqr  = ""
            dqt  = ""
            #dqu  = ""
            dmoc = ""
            fb.seek(hit_dqr+25)
            raw_text = fb.read(10)
            find = re.findall( r'[0-9 MGT\.,]*B', raw_text)
            if len(find) > 0:
                dqr = "DisplayQuotaRemaining: " + str(find[0])  #DisplayQuotaRemaining
            fb.seek(hit_dqr+25)
            raw_text = fb.read(100)
            find = re.findall( r'displayQuotaTotal[\":0-9 MGT\.,]*B', raw_text) #displayquotatotal
            if len(find) > 0:
                dqt = str(find[0]).replace('"',"").replace(":", "    : ")
            fb.seek(hit_dqr-130)
            raw_text = fb.read(130)
            find = re.findall( r'dateModifiedOnClient[\":0-9 ]*', raw_text) #dateModifiedOnClient
            if len(find) > 0:
                dmoc = find[0].replace('"',"")
                dmoc = f_timestamp_tick(dmoc)
                dmoc = "DateModifiedOnClient : " + str(dmoc)
            sms_complete = dmoc + "\t" + dqr + "\t" +  dqt
            if sms_complete.count(':') >=3 :
                od_quota_list.append(sms_complete)
                
    od_quota_list = set(od_quota_list)
    od_quota_list = sorted(list(od_quota_list))
    
    if len(od_quota_list) > 0:
        print "\n****************************************\n OneDrive - Disk Quota and Usage (%s)\n****************************************" % str(len(od_quota_list))
        for i in od_quota_list:
            print "\n" + i.replace("\t","\n")

# **************************************************************************************************************************************************
# OneDrive - Files Uploaded #livefilestore
# **************************************************************************************************************************************************

def af_onedrive_files_uploaded():
    od_download_list=[]
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_od_download)
    
    for hit in hits:
        a="" #name
        b="" #estension
        c="" #displaysize
        d="" #lastaccess
        e="" #modifieddate
        f="" #ownername
        g="" #sharinglevel
        h="" #url
        fb.seek(hit-900)
        raw_text=fb.read(900).split(',')
        for i in raw_text:
            if "name" in i:
                if "cropped" not in i and "scaled" not in i:
                    a = i.replace('\"','').replace(":","        : ")
            elif "extension" in i:
                b =  i.replace('\"','').replace(":","   : ") 
            elif "displaySize" in i:
                c = i.replace('\"','').replace(":"," : ") 
            elif "lastAccess" in i:
                d = f_timestamp_tick(i)
                d = "lastAccess  : " + str(d) 
            elif "modifiedDate" in i:
                e = f_timestamp_tick(i)
                e = "modifiedDate: " + str(e)
            elif "ownerName" in i:
                f = i.replace('\"','').replace(":","   : ") 
            elif "sharingLevel\"" in i:
                g = i.replace('\"','').replace(":",": ") 
        fb.seek(hit+20)
        raw_text=fb.read(300).split('"')
        raw_text=raw_text[0].replace("\\","")
        find = re.findall(r'(?:https|http):[0-9a-zA-Z:/\.\-\=_%?&+]*', raw_text) #look for URLs
        if find:
            h = "URL         : " + find[0]
        i = a + ";" + b+ ";" + c+ ";" + d+ ";" + e+ ";" + f+ ";" + g + ";" + h
        od_download_list.append(i)
    
    od_download_list = set(od_download_list)
    od_download_list = sorted(list(od_download_list))
    
    ii=0
    for i in od_download_list: #URLs with details
        if i.count(":") > 2:
            ii+=1
    
    if ii > 0:
        print "\n********************************************\n OneDrive - Uploaded Files (with details) (%d) \n********************************************" % ii
    
    temp = []
    
    for i in od_download_list:
        #URLs with details 
        if i.count(":") > 2: 
            print "\n" + i.replace(";;",";").replace(";","\n").replace("\n\n\n","")
        #URLs only
        else:                
            full_url = i.replace(";;",";").replace(";","\n").replace("\n\n\n","").replace("URL         : ","")
            odufile = full_url[full_url.rfind("/")+1:full_url.rfind("?")] #odufile = OneDriveUploadedFile
            temp.append(odufile)
            
    temp = set(temp)
    temp = sorted(list(temp))
    
    if len(temp) > 0:
        print "\n****************************************\n OneDrive - List of Uploaded Files (URLs only) (%d) \n****************************************" % len(temp)
    
    for i in temp:
        print i

   
# **************************************************************************************************************************************************    
# SMTP (store.vol)
# **************************************************************************************************************************************************

def af_email_smtp():
    hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_smtp_email_address)
    smtp_value_list=[]
    
    for hit in hits:
        fb.seek(hit)
        fb.seek(hit+6)
        raw_text=fb.read(100)    
        email = re.findall( r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b', raw_text)
        if len(email)>0:
                smtp_value_list.append(email[0].lower())
        else:
            pass
      
    smtp_value_list=set(smtp_value_list)
    smtp_value_list=sorted(list(smtp_value_list))
    
    if len(smtp_value_list) > 0:
        print "\n********************************************\n E-mail addresses found by searching the keyword SMTP (%s)\n*******************************************" % str(len(smtp_value_list))
        print "\nE-mail addresses (Sent to / Received from)\n"
        for i in smtp_value_list :
            print i

# *************************************************************************************************************************************************
# Wireless SSID (\Windows\Wlan\CommonAppData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\{GUID}.xml
# *************************************************************************************************************************************************

def af_wifi_ssid():
    hits1 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_ssid_start)
    
    ssid_list=[]

    for hit1 in hits1:  #sig_ssid_start
        fb.seek(hit1+17)
        try:
            raw_text=str(fb.read(30)).split("</name>")
            ssid_list.append(raw_text[0])
        except:
            pass

    ssid_list=set(ssid_list)
    ssid_list=sorted(list(ssid_list))
    
    if len(ssid_list)>0:
        print "\n****************************************\n Wireless SSIDs to which the device has connected (%s)\n****************************************\n" % str(len(ssid_list))
        for i in ssid_list:
            print i

# **************************************************************************************************************************************************
# contacts (store.vol)
# **************************************************************************************************************************************************

def af_contacts():
    temp  = [] #generic strings with letters
    temp2 = [] #strings found in temp translated into hex
    temp3 = [] #text + phone number
    
    if 'store.vol' in sys.argv[1]:
        print "\n****************************************\n Contacts (partial extraction)\n****************************************\n"
        with open(sys.argv[1], "rb") as ftext:
            text = ftext.read()
            find = re.findall(r'[A-Za-z\'����� ]{2,20}', text) #search text
            find = set(find)
            find = sorted(list(find))
            for i in find:
                if len(i)>3:
                    temp.append(i)
        for i in temp:
            a  =':'.join(x.encode('hex') for x in i)
            c1 = r"\x80\x" + a.replace(":",r'\x')         #contact version 1 (�) - from string into hex
            c2 = r"\x92\x00\x" + a.replace(":",r'\x')     #contact version 2 ('.) - from string into hex
            c3 = r"\x5e\x00\x" + a.replace(":",r'\x')     #contact version 3 (^.) - from string into hex
            c4 = r"\x80\x39\x00\x" + a.replace(":",r'\x') #contact version 4 (�9.) - from string into hex
            temp2.append(c1) 
            temp2.append(c2) 
            temp2.append(c3) 
            temp2.append(c4)
        for i in temp2:
            f = i.replace(r'\x',"").decode('hex')
            if f[1:].lower() != "content":
                hits = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, i)   #hex hits of contact versions
                for hit in hits:
                    fb.seek(hit+len(f))
                    raw_text=fb.read(40)
                    raw_text=raw_text.replace(".","")
                    find = re.findall(r'[0-9 +]{3,30}', raw_text) #retrieve phone numbers
                    if find:
                        temp3.append(f[1:] + ": " + str(find[0])) #skip first character
        temp3=set(temp3)
        temp3=sorted(list(temp3))
        for i in temp3:
            print i

# **************************************************************************************************************************************************
# phone call log (partial extraction) (pim.vol)
# **************************************************************************************************************************************************

def af_call_log():
    if 'pim.vol' in sys.argv[1]:
        temp  = []
        print "\n****************************************\n Phone Call Log (partial extraction)\n****************************************\n"
        with open(sys.argv[1], "rb") as ftext:
            text = ftext.read().replace("\x00\x00\x20\x00","").replace("\x00\x6F\x00"," ").replace("\x00\x47"," ").replace("\x00\x57"," ").replace("\x00\x57\x00"," ").replace("\x00"," ").replace("\xE0","a'")
            find = re.findall(r'\x80[0-9+][A-Za-z0-9+\' ]*', text)
            find = set(find)
            find = sorted(list(find))
            for i in find:
                if len(i)>3 and "clog" not in i: #clog is a false positive
                    temp.append(i)
        for i in temp:
            print i[1:] #remove first character


# *************************************************************************************************************************************************
# SMS
# Text message structure:
# <timestamp 6 bytes> hit_sms_pre (40 00 07 00 0A) <message type 0x21 sent, 0x5d received > |
# hit_sms_header (IPM.SMStext) | <message body> | hit_sms_footer (..SMS..)
# **************************************************************************************************************************************************

def af_sms():
    hits_sms_pre1 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_pre1)
    hits_sms_pre2 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_pre2)
    hits_sms_pre3 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_pre3)
    hits_sms_pre4 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_pre4)
    hits_sms_pre  = hits_sms_pre1 + hits_sms_pre2 + hits_sms_pre3 + hits_sms_pre4
    hits_sms_pre  = set(hits_sms_pre)
    hits_sms_pre  = sorted(list(hits_sms_pre))
    
    hits_sms_header1 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_header1)
    hits_sms_header2 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_header2)
    hits_sms_header  = hits_sms_header1 + hits_sms_header2
    hits_sms_header  = set(hits_sms_header)
    hits_sms_header  = sorted(list(hits_sms_header))
     
    hits_sms_footer1 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_footer1)
    hits_sms_footer2 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_footer2)
    hits_sms_footer3 = sliceNsearchRE(fb, CHUNK_SIZE, DELTA, sig_sms_footer3)
    hits_sms_footer  = hits_sms_footer1 + hits_sms_footer2 + hits_sms_footer3
    hits_sms_footer  = set(hits_sms_footer)
    hits_sms_footer  = sorted(list(hits_sms_footer))
    
    filename = "sms_output.csv"
    
    f = codecs.open("sms_output.csv", 'w', 'utf-8')
    f.write(u'\ufeff') #added for Excel compatibility
    f.write("Offset\tTimestamp (YYYY-MM-DD hh:mm:ss)\tMessage Type\tPhone number\tMessage body\n")
    f.close()
    
    found_counter = 0 #used to count the number of recovered text messages

    print "\n" + "*" * 55
    print " SMS (sent messages lack the recipient's phone number)"
    print "*" * 55

    for hit_sms_footer in hits_sms_footer:
        offsets_to_check = []
        sms_date         = ""
        sms_type         = ""
        sms_typev        = "" #message type description (verbose): sent, received
        sms_phone        = ""
        sms_body         = ""
        sms_offset       = ""
        try:
            for hit_sms_header in hits_sms_header:
                if hit_sms_header < hit_sms_footer and hit_sms_footer-hit_sms_header < 500: #compare offsets
                    offsets_to_check.append(hit_sms_header) #list of possible hit_sms_header
            hit_sms_header = min(offsets_to_check, key=lambda x:abs(x-hit_sms_footer)) #find the closest hit_sms_header to the hit_sms_footer
            fb.seek(hit_sms_header)
            raw_body = fb.read(hit_sms_footer-hit_sms_header)
            sms_body = raw_body[12:].replace('\x0D', '').replace('\x0A', '').replace('\x09', '')
            #\x0A new line, \x0D carriage return, \x09 horizontal tab
            #sms_body = filter(lambda x: x in string.printable, sms_body)
            
            #remove noise
            noise = ['\x00','\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08','\x0B','\x0C','\x0E','\x0F','\x10','\x11',
                     '\x12','\x13','\x14','\x18','\x19','\x1A','\x1D','\x1F','\x7F','\x80','\x80\x09','\x81','\x82','\x83',
                     '\x84','\x85','\x88','\x90','\x94','\x98','\x99','\xF5\x6F','\xFF','\x8A','\xA0','\x1A']
            while True:
                for i in noise:
                    if i in sms_body:
                        sms_body = sms_body.replace(i,'')
                break
            
            #remove additional noise
            if sms_body.startswith('t'):
                sms_body = sms_body[1:]
            elif sms_body.startswith('ext'):
                sms_body = sms_body[4:]
            elif sms_body.startswith('o'):
                sms_body = sms_body[1:]
            elif sms_body.startswith('xt'):
                sms_body = sms_body[2:]
            elif sms_body[1] == " ":
                sms_body = sms_body[2:]
            elif sms_body.startswith("?"):
                sms_body = sms_body[1:]
            elif sms_body.startswith("@"):
                sms_body = sms_body[1:]
                                            
            sms_body = sms_body.decode('latin_1',"ignore")
            offsets_to_check = []
            for hit_sms_pre in hits_sms_pre:
                if hit_sms_pre < hit_sms_header and hit_sms_header-hit_sms_pre < 500: #compare offsets
                    offsets_to_check.append(hit_sms_pre) #list of possible hit_sms_pre
        except:
            pass
        try:
            hit_sms_pre = min(offsets_to_check, key=lambda x:abs(x-hit_sms_footer)) #find the closest hit_sms_pre to the hit_sms_footer
            sms_offset = str(hit_sms_pre)
            fb.seek(hit_sms_header-18)
            raw_text=fb.read(18) 
            allowed_chars = ['+','0','1','2','3','4','5','6','7','8','9'] #allowed characters in a phone number
            for allowed_char in range(0, len(raw_text)):
                if raw_text[allowed_char] in allowed_chars:
                    sms_phone = sms_phone+raw_text[allowed_char]
            
            #phones = re.findall(r'[0-9+]*', raw_text) #look for phone numbers

            fb.seek(hit_sms_pre-6) # grab the timestamp: read 6 bytes before 0x40 00 07 00 0A
            
            # Timestamp parsing provided by Vincent ECKERT 
            
            hex_ms      = binascii.hexlify(fb.read(6))
            hour        = binascii.hexlify(struct.pack('<L',int(hex_ms[0:8],16)))
            hour        = time.strftime('%H:%M:%S', time.gmtime(int(hour,16)/1000))
            mstime      = binascii.hexlify(struct.pack('<H',int(hex_ms[8:12],16)))
            date        = datetime(1900,1,1)+timedelta(int(mstime,16))
            date_string = str(date)
            date_string = date_string[:10] #grab the first 10 characters: YYYY-MM-DD
            sms_date    = date_string + "  " + hour + " " + "(UTC)"
            #sms_date = '{}/{}/{}'.format(date.day,date.month,date.year),hour,'UTC'
            #sms_date = '{}-{}-{}'.format(date.year,date.month,date.day),hour,'UTC'

            #read and check message type
            fb.seek(hit_sms_pre + 5 + 4)
            sms_type = binascii.hexlify(fb.read(2))
            if '21' in sms_type:
                sms_typev = "Sent"
                sms_phone = "TO: N/A"
            elif '5d' in sms_type:
                sms_typev = "Received"
                if sms_phone == "" or len(sms_phone)<3:
                    sms_phone = "FROM: N/A"
                else:
                    sms_phone = "FROM: " + sms_phone
            else:
                if len(sms_phone) >= 3:
                    sms_typev = "Received"
                    sms_phone = "FROM: " + sms_phone
                else:
                    sms_typev = "N/A"
                    sms_phone = "N/A"
            
            if sms_body <> "" and sms_phone <> "": #discard if sms_body and sms_phone are blank (invalid message block)
                #print "\nOFFSET: %s\nDATE  : %s\nTYPE  : %s\n%s\nBODY  : %s" % (sms_offset,sms_date,sms_typev,sms_phone,sms_body)
                sms = sms_offset + "\t" + sms_date + "\t" + sms_typev + "\t" + sms_phone + "\t" + sms_body + "\n"
                found_counter += 1
                f = open(filename,"ab")
                f.write(sms.encode('utf-8'))
                f.close()
                if found_counter % 50 == 0: #print status every 50 messages
                    print "..."
                    print "\nNumber of messages found: %d" % found_counter  
        except:
            pass
    
    print "\n<< Found %d text message(s) (SMS) >>" % found_counter
    
    
    if found_counter > 0:
        print "\nText messages exported to %s\%s\n(TAB delimited text file)" % (os.getcwd(),filename)
    else:
        os.remove(filename)
   
    
# **************************************************************************************************************************************************
# MAIN
# **************************************************************************************************************************************************

os.system('cls')

start_time = datetime.now()

print "\n\nScript started: " + str(start_time)
for op in sys.argv[2:]:
    if op == "-a":    #account information
        af_account()
        af_account_create_time()
    elif op == "-d":  #device artifacts
        af_imei()
        af_sim_imsi()
        af_last_sim_imsi()
        af_wifi_adapter_mac()
        af_friendly_name()
        af_last_shutdown()
    elif op == "-g":  #gps
        af_gps_last_known_location()
        af_gps_lastposinjected()
        af_gps_location_syncstart()
    elif op == "-h":  #Internet Explorer History
        af_ie_typed_urls()
    elif op == "-ip": #DHCP IP Address
        af_dhcp()
        af_gprs_ipaddress()
    elif op == "-o":  #OneDrive artifacts
        af_onedrive_disk_quota()
        af_onedrive_files_uploaded()
    elif op == "-p":  #Personal information
        af_contacts()
        af_call_log()
        af_email_smtp()
    elif op == "-s":  #SMS messages
        af_sms()
    elif op == "-w":  #Wireless connections
        af_bluetooth()
        af_wifi_ssid()
    elif op == "-i":   #AppID
        af_appid()
    elif op == "-all": #Extract all artifacts
        af_imei()
        af_wifi_adapter_mac()
        af_friendly_name()
        af_last_shutdown()
        af_sim_imsi()
        af_last_sim_imsi()
        af_gps_last_known_location()
        af_gps_lastposinjected()
        af_gps_location_syncstart()
        af_account()
        af_account_create_time()
        af_contacts()
        af_call_log()
        af_sms()
        af_email_smtp()
        af_ie_typed_urls()
        af_bluetooth()
        af_wifi_ssid()
        af_dhcp()
        af_gprs_ipaddress()
        af_appid()
        af_onedrive_disk_quota()
        af_onedrive_files_uploaded()
    else:
        welcome()
        
end_time = datetime.now()
print "\n\nScript started : " + str(start_time)
print "Script finished: " + str(end_time)
print('Duration       : {}'.format(end_time - start_time))
