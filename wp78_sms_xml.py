#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Gabriele Zambelli (Twitter: @gazambelli)
# Blog  : http://forensenellanebbia.blogspot.it
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
#
#
# Python script to parse the following artifacts from a Windows 7.8 phone:
#
# - SMS text messages carved out in the XML format
#

# Change history
# 2015-09-04 First public release (v 0.1)


# *********************************************************************************************************************************************************
# Welcome
# *********************************************************************************************************************************************************

from datetime import datetime,timedelta
import os
import re
import sys
import string

def welcome():
    os.system('cls')
    print "\n\n Windows Phone 7.8 - Parser for carved SMS messages in XML format\n\n"
    print " How to use ==> python wp78_parser.py folder_to_parse\n\n"
    print " Type the path of the folder containing the SMS messages\n in XML format that you previously carved out\n\n"

welcome()

if len(sys.argv) > 1:
    if os.path.exists(sys.argv[1]) == True:
        pass
    else:
        welcome()
        sys.exit()
else:
    welcome()
    sys.exit()


os.system('cls')

dir      = sys.argv[1]

files    = os.listdir(dir)
files_wp = [i for i in files if i.endswith('.sms')]


# *********************************************************************************************************************************************************
# FUNCTIONS
# *********************************************************************************************************************************************************

# -- BEGIN -- From https://github.com/cheeky4n6monkey/4n6-scripts/blob/master/wp8-callhistory.py -- BEGIN --

# Find all indices of the "pattern" regular expression in a given string (using regex)
# Where pattern is a compiled Python re pattern object (ie the output of "re.compile")

CHUNK_SIZE = 80000000 #80MB   2000000000 # max value of CHUNK_SIZE + DELTA is 2147483647 (C long limit with Python 2)
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
def filetime(data):
    #invert byte order for conversion
    dt=data[14]+data[15]+data[12]+data[13]+data[10]+data[11]+data[8]+data[9]+data[6]+data[7]+data[4]+data[5]+data[2]+data[3]+data[0]+data[1]
    us = int(dt,16) / 10
    conversion= datetime(1601,1,1) + timedelta(microseconds=us)
    return conversion

def replace_text(raw_text):
    raw_text=raw_text.split('SMS')
    raw_text=raw_text[0]
    raw_text=raw_text.replace("\xFF\xFF\x3F\x00","").replace("\x07\x04\x00","").replace("\xFF\xFF\x7F\x40","")
    raw_text=raw_text.replace("\xFF\xFF\x0F\x00","").replace("\xFF\xFF\xFF","").replace("\x0F\x00\x00\x00","").replace("\xFF\xFF","")
    raw_text=raw_text.replace("\xE8","e'").replace("\xE9","e'").replace("\xE0","a'").replace("\xF2","o'").replace("\xF9","u'").replace("\xEC","i'")
    filtered_body = filter(lambda x: x in string.printable, raw_text)
    return filtered_body

# *********************************************************************************************************************************************************
# SIGNATURES
# *********************************************************************************************************************************************************

# *** SMS XML ***
ipmsmstext2        = "\x3E\x49\x50\x4D\x2E\x53\x4D\x53\x74\x65\x78\x74\x3C\x2F\x50\x72\x6F\x70\x65\x72\x74\x79\x3E" # >IPM.SMStext</Property> = beginning of a text message
ipmsmstext2_body   = "\x30\x78\x33\x37\x30\x30\x31\x66" # <Property Name="0x37001f"> = body
ipmsmstext2_phone  = "\x30\x78\x33\x30\x30\x33\x30\x30\x31\x66" # 0x3003001f" = phone number
ipmsmstext2_marker = "\x3C\x2F\x50\x72\x6F\x70\x65\x72\x74\x79\x3E\x3C\x50\x72\x6F\x70\x65\x72\x74\x79" # </Property><Property = end of field

#<Property Name="0xe070003"> 21=sent, 1=received - offset from >IPM.SMStext</Property> = 23
ipmsmstext2_tofrom = "\x3C\x50\x72\x6F\x70\x65\x72\x74\x79\x20\x4E\x61\x6D\x65\x3D\x22\x30\x78\x65\x30\x37\x30\x30\x30\x33\x22\x3E"

# <Property Name="0xe060040"> = timestamp (received/sent)
ipmsmstext2_date   = "\x3C\x50\x72\x6F\x70\x65\x72\x74\x79\x20\x4E\x61\x6D\x65\x3D\x22\x30\x78\x65\x30\x36\x30\x30\x34\x30\x22\x3E"


# *********************************************************************************************************************************************************
# SMS xml - from CommsBackup.xml generated by WP automatic backup 
# *********************************************************************************************************************************************************
# Order of fields: beginning (IPM.SMStext), Sent(21)/Received(1) (<Property Name="0xe070003">), date (<Property Name="0xe060040">), body (<Property Name="0x37001f">), phone number (<Property Name="0x3003001f">) 
# </Property><Property = generic end and start of a new field

def find_tofrom(hit1):
    raw = ""
    if hit1+23 in hits_tofrom:
        fb.seek(hit1+23+33)
        raw = fb.read(2)
    elif hit1+22 in hits_tofrom:
        fb.seek(hit1+22+33)
        raw = fb.read(2)
    if raw  == "21": #sent
        tofrom = "To  : "
    elif raw == "01": #received
        tofrom = "From: "
    else:
        tofrom = "N/A : "
    return tofrom

def accents(text):
    text = text.replace("\xE8","e'").replace("\xE9","e'").replace("\xE0","a'").replace("\xF2","o'")
    text = text.replace("\xC3\xAC","i'").replace("\xC3\xA8","e'").replace("\xC3\xA9","e'").replace("\xC3\xB2","o'")
    text = text.replace("\xC3\xB9","u'").replace("\xC3","a'").replace("\x26\x69\x67\x72\x61\x76\x65\x3B","i'")
    return text

os.chdir(dir)

sms = []

f=open("sms_xml.csv","w")
f.write("Date\tText\tFrom / To\tFile\n")

for file in files_wp:
    fb = open(file,"rb")

    hits_sms    = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2)
    hits_tofrom = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2_tofrom)
    hits_date   = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2_date)
    hits_body   = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2_body)
    hits_marker = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2_marker)
    hits_phone  = sliceNsearchRE(fb, CHUNK_SIZE, DELTA,ipmsmstext2_phone)
    
    for hit_sms in hits_sms: #sms
        status=find_tofrom(hit_sms)
        if hit_sms+115 in hits_date:
            fb.seek(hit_sms+115+27)
            raw_date=fb.read(16)
            raw_date2 = r'\x'.join(x.encode('hex') for x in raw_date) #translate from ascii text to hex code
            raw_date2 = r"\x" + raw_date2 #prepend \x at the beginning
            f = raw_date2.replace(r'\x',"").decode('hex')
            try:
                us = int(f,16)/10
                conversion= datetime(1601,1,1) + timedelta(microseconds=us)
                if str(conversion).startswith("20"):
                    sms_date = "Date: " + str(conversion) + " (UTC)"
                else:
                    sms_date = "not found"
            except:
                sms_date = "not found"
        for hit_body in hits_body:
            if hit_body > hit_sms+115: #don't go over the next sms message
                fb.seek(hit_body+10)
                raw_body=fb.read(400).replace("\x0D", " ").replace("\x0A", " ") #remove carriage return and line feed from text
                raw_body=raw_body.split("\x3C\x2F\x50\x72\x6F\x70\x65\x72\x74\x79\x3E") #means </property>
                raw_body=accents(raw_body[0])
                sms_body = "Text: " + raw_body #filter(lambda x: x in string.printable, raw_body[0])
        for hit_phone in hits_phone:
            if hit_phone > (hit_sms+115): #don't go over the next sms message
                fb.seek(hit_phone+12)
                raw_phone=fb.read(28).split("\x3C\x2F\x50\x72\x6F\x70\x65\x72\x74\x79\x3E") #means </property>
                find=re.findall(r'[0-9+]*', raw_phone[0])
                if find[0]:
                    sms_phone = status + find[0]
                    final = sms_date + "\t" + sms_body + "\t" + sms_phone + "\n" #+ "\t" + file + "\n"
                    sms.append(final)  
        
dup = str(len(sms))

sms = set(sms)
sms = sorted(list(sms))

f=open("sms_xml.csv","ab")

print "\n**************************************** \nSMS (From %s to %s) (recovered from xml backup)\n****************************************\n" % (dup, str(len(sms)))
print "Written to output file: sms_xml.csv\n"

for i in sms:
    f.write(i) 
    
