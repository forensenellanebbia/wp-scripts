#!/usr/bin/python2.7 -S
# -*- coding: utf-8 -*-
#
# Author: Gabriele Zambelli (Twitter: @gazambelli)
# Blog  : http://forensenellanebbia.blogspot.it
#
# WARNING: This program is provided "as-is"
# See http://forensenellanebbia.blogspot.it/2016/04/whatsapp-chat-parser-for-windows-phone.html for further details.

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
# WhatsApp chat parser for Windows Phone 7.8: the script saves the output in HTML and CSV format
# (tested against WhatsApp v2.11.670 for Windows Phone 7.8)
#
# Change history
# 2016-04-02 First release
#
#
# Prerequisites
# - Python v2.7
# - Javascript library "sorttable.js" (http://freepages.genealogy.rootsweb.ancestry.com/~gearyfamily/expression-web/sort-table.html)
#   put this file in the same folder where you have exported your WhatsApp database
#  
# If you get the error "sqlite3.DatabaseError: file is encrypted or is not a database" when running the script,
# you have to update the sqlite3.dll file in your "C:\Python27\DLLs" path. Download the most recent one from
# https://www.sqlite.org/download.html


from datetime import datetime
import binascii
import os
import shutil
import sqlite3 as lite
import sys
import urllib2

try:
    os.system('cls')
except:
    os.system('clear')

if len(sys.argv)<2:
    print "\n\n WhatsApp chat parser for Windows Phone 7.8\n"
    print " How to use ==> python wp78_wa.py messages.db\n\n"
    print " [The output will be automatically saved in HTML and CSV format]\n\n"
    sys.exit()
else:
    pass

start_time = datetime.now()
print "\n\nScript started: " + str(start_time)

print "\n...parsing..."


# ************************ CSV OUTPUT ************************

conn              = lite.connect(sys.argv[1])
conn.text_factory = str
cursor            = conn.cursor()

sql = 'SELECT messages.messageid,messages.keyremotejid,messages.KeyFromMe,messages.keyid,messages.status,messages.data,hex(messages.binarydata) AS BinaryData,hex(messagemiscinfos.largethumbnaildata) AS LargeThumbnailData,datetime(messages.timestamplong,"unixepoch", "utc") AS TimestampLong,datetime(messages.creationtimelong,"unixepoch","utc") AS CreationTimeLong,messages.pushname,mediaurl,messages.mediamimetype,messages.mediasize,messages.mediadurationseconds,messages.medianame,messages.localfileuri,messages.latitude,messages.longitude,messages.mediacaption FROM messages LEFT JOIN messagemiscinfos ON messages.messageid=messagemiscinfos.messageid'

cursor.execute(sql)
rows = cursor.fetchall() 

f_csv_name = "wa_output.csv"
f_csv = open(f_csv_name,'w')
f_csv.close()
f_csv = open(f_csv_name, 'ab')

f_csv.write("MessageId\t")
f_csv.write("KeyremoteJid\t")
f_csv.write("KeyFromMe\t")
f_csv.write("KeyId\t")
f_csv.write("Status\t")
f_csv.write("Data\t")
f_csv.write("BinaryData\t")
f_csv.write("TimestampLong (UTC)\t")
f_csv.write("CreationTimeLong (UTC)\t")
f_csv.write("PushName\t")
f_csv.write("MediaUrl\t")
f_csv.write("MediaMimeType\t")
f_csv.write("MediaSize\t")
f_csv.write("MediaDurationSeconds\t")
f_csv.write("MediaName\t")
f_csv.write("LocalFileUri\t")
f_csv.write("Latitude\t")
f_csv.write("Longitude\t")
f_csv.write("MediaCaption\n")

for row in rows:
    messageid            = str(row[0]) 
    keyremotejid         = str(row[1]) 
    keyfromme            = str(row[2]) 
    keyid                = str(row[3]) 
    status               = str(row[4]) 
    data                 = str(row[5]) 
    binarydata           = str(row[6]) 
    timestamplong        = str(row[8]) 
    creationtimelong     = str(row[9]) 
    pushname             = str(row[10]) 
    mediaurl             = str(row[11]) 
    mediamimetype        = str(row[12]) 
    mediasize            = str(row[13])
    mediadurationseconds = str(row[14])
    medianame            = str(row[15])
    localfileuri         = str(row[16])
    latitude             = str(row[17])
    longitude            = str(row[18])
    mediacaption         = str(row[19])

    if keyfromme == "0": #check status
        status = "RECEIVED (%s)" % status
    else:
        status = "SENT (%s)" % status
    if data <> "None": 
        data = data.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    else:
        data = ""
    if "FFD8" in binarydata:
        binarydata = "<see html file>"
    else:
        binarydata = ""
    if '1969' in timestamplong:
        timestamplong = ""
    if creationtimelong == "None":
        creationtimelong = ""
    if pushname == "None":
        pushname = ""
    if mediaurl == "None":
        mediaurl = ""
    if mediamimetype == "None":
        mediamimetype = ""
    if medianame == "None":
        medianame = ""
    if localfileuri == "None":
        localfileuri = ""
    if mediacaption <> "None":
        mediacaption = mediacaption.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    else:
        mediacaption = ""
    f_csv.write(messageid + "\t")
    f_csv.write(keyremotejid + "\t")
    f_csv.write(keyfromme + "\t")
    f_csv.write(keyid + "\t")
    f_csv.write(status + "\t")
    f_csv.write(data + "\t")
    f_csv.write(binarydata + "\t")
    f_csv.write(timestamplong + "\t")
    f_csv.write(creationtimelong + "\t")
    f_csv.write(pushname + "\t")
    f_csv.write(mediaurl + "\t")
    f_csv.write(mediamimetype + "\t")
    f_csv.write(mediasize + "\t")
    f_csv.write(mediadurationseconds + "\t")
    f_csv.write(medianame + "\t")
    f_csv.write(localfileuri + "\t")
    f_csv.write(latitude + "\t")
    f_csv.write(longitude + "\t")
    f_csv.write(mediacaption + "\n")

f_csv.close()


# ************************ HTML OUTPUT ************************

sql = 'SELECT DISTINCT keyremotejid FROM messages' #unique keyremotejid

cursor.execute(sql)
keyremotejids = cursor.fetchall() 

#create HTML page and add html header
for keyremotejid in keyremotejids:
    # long output (l)
    filename_l = str(keyremotejid[0]) + ".htm" 
    f_htm_l    = open(filename_l,'w')

    htm_header_p1 = "<!DOCTYPE html>\n<HTML>\n<HEAD>\n<meta charset='utf-8'/>\n \
        <title>" + filename_l[:-4] + "</title>\n"
        
    table_style_l = "<style>table, th, td {border-collapse:collapse;font-size:11pt;border:solid 1px solid black;word-wrap:break-word; \
        width:150%;table-layout:fixed;}"
        
    table_style_s = "<style>table, th, td {border-collapse:collapse;font-size:11pt;border:solid 1px solid black;word-wrap:break-word; \
        width:70%;table-layout:fixed;}"
        
    htm_header_p2 = "tbody tr:hover {  background: yellow;}</style>\n \
        <script src='sorttable.js' type='text/javascript'></script>\n \
         </HEAD>\n<BODY>\n \
         <table BORDER=1 class='sortable'>\n \
         <thead>\n<TR bgcolor='#00FF00'>\n" #first row is the header - green color
   
    f_htm_l.write(htm_header_p1 + table_style_l + htm_header_p2)

    f_htm_l.write('  <TH style="width:80px;">MessageId</TH>\n')
    f_htm_l.write('  <TH style="width:200px;">KeyremoteJid</TH>\n')
    f_htm_l.write('  <TH style="width:90px;">KeyFromMe</TH>\n')
    f_htm_l.write('  <TH style="width:160px;">KeyId</TH>\n')
    f_htm_l.write('  <TH style="width:110px;">Status</TH>\n')
    f_htm_l.write('  <TH style="width:200px;">Data</TH>\n')
    f_htm_l.write('  <TH style="width:100px;">BinaryData</TH>\n')
    f_htm_l.write('  <TH style="width:340px;">LargeThumbData</TH>\n')
    f_htm_l.write('  <TH style="width:130px;">TimestampLong (UTC)</TH>\n')
    f_htm_l.write('  <TH style="width:130px;">CreationTimeLong (UTC)</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">PushName</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaUrl</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaMimeType</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaSize</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaDurationSeconds</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaName</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">LocalFileUri</TH>\n')
    f_htm_l.write('  <TH style="width:90px;">Latitude</TH>\n')
    f_htm_l.write('  <TH style="width:90px;">Longitude</TH>\n')
    f_htm_l.write('  <TH style="width:140px;">MediaCaption</TH>\n</TR>\n</THEAD>\n')
    f_htm_l.close()
    
    # short output (s)
    filename_s = str(keyremotejid[0]) + "_short.htm" 
    f_htm_s    = open(filename_s,'w')
    
    f_htm_s.write(htm_header_p1 + table_style_s + htm_header_p2)
    
    f_htm_s.write('  <TH>MessageId</TH>\n')
    f_htm_s.write('  <TH>KeyremoteJid</TH>\n')
    f_htm_s.write('  <TH>Status</TH>\n')
    f_htm_s.write('  <TH>Data</TH>\n')
    f_htm_s.write('  <TH>BinaryData</TH>\n')
    f_htm_s.write('  <TH>TimestampLong (UTC)</TH>\n')
    f_htm_s.write('  <TH>CreationTimeLong (UTC)</TH>\n')
    f_htm_s.write('  <TH>PushName</TH>\n</TR>\n</THEAD>')
    f_htm_s.close()

#populate table
for keyremotejid in keyremotejids:
    sql = 'SELECT messages.messageid,messages.keyremotejid,messages.KeyFromMe,messages.keyid,messages.status,messages.data,hex(messages.binarydata) AS BinaryData,hex(messagemiscinfos.largethumbnaildata) AS LargeThumbnailData,datetime(messages.timestamplong,"unixepoch", "utc") AS TimestampLong,datetime(messages.creationtimelong,"unixepoch","utc") AS CreationTimeLong,messages.pushname,mediaurl,messages.mediamimetype,messages.mediasize,messages.mediadurationseconds,messages.medianame,messages.localfileuri,messages.latitude,messages.longitude,messages.mediacaption FROM messages LEFT JOIN messagemiscinfos ON messages.messageid=messagemiscinfos.messageid WHERE messages.keyremotejid LIKE "%s"' % keyremotejid
    cursor.execute(sql)
    rows     = cursor.fetchall()
    filename_l = str(keyremotejid[0]) + ".htm"
    f_htm_l    = open(filename_l,'ab') 
    filename_s = str(keyremotejid[0]) + "_short.htm"
    f_htm_s    = open(filename_s,'ab')
    for row in rows:
        messageid            = str(row[0]) 
        keyremotejid         = str(row[1]) 
        keyfromme            = str(row[2]) 
        keyid                = str(row[3]) 
        status               = str(row[4]) 
        data                 = str(row[5]) 
        binarydata           = str(row[6]) 
        largethumbdata       = str(row[7])
        timestamplong        = str(row[8]) 
        creationtimelong     = str(row[9]) 
        pushname             = str(row[10]) 
        mediaurl             = str(row[11]) 
        mediamimetype        = str(row[12]) 
        mediasize            = str(row[13])
        mediadurationseconds = str(row[14])
        medianame            = str(row[15])
        localfileuri         = str(row[16])
        latitude             = str(row[17])
        longitude            = str(row[18])
        mediacaption         = str(row[19])
        
        if keyfromme == "0": #create new row: color based on keyfromme
            f_htm_l.write("\n<TR bgcolor='#F9DDA6'>\n") #http://www.rapidtables.com/web/color/RGB_Color.htm
            f_htm_s.write("\n<TR bgcolor='#F9DDA6'>\n")
        else:
            f_htm_l.write("\n<TR>\n")
            f_htm_s.write("\n<TR>\n")
        if keyfromme == "0": #check status
            status = "RECEIVED (%s)" % status
        else:
            status = "SENT (%s)" % status
        if data <> "None":
            data = data.replace("\n", "").replace("\r", "") #field: data (message)
        else:
            data = ""
        if "FFD8" in binarydata: #decode binarydata (small thumbnail)
            datahex = binarydata.decode("hex")
            base = binascii.b2a_base64(datahex)
            f_jpg_name = keyremotejid + '_' + messageid + '_s.jpg'
            f_jpg = open(f_jpg_name,'wb')
            f_jpg.write(binascii.unhexlify(binarydata))
            f_jpg.close()
            binarydata = '<img src="data:image/jpeg;base64,' + base + '" alt="Embedded Image" />'
        if "FFD8" in largethumbdata: #decode largethumbdata (large thumbnail)
            datahex = largethumbdata.decode("hex")
            base = binascii.b2a_base64(datahex)
            f_jpg_name = keyremotejid + '_' + messageid + '_l.jpg'
            f_jpg = open(f_jpg_name,'wb')
            f_jpg.write(binascii.unhexlify(largethumbdata))
            f_jpg.close()
            largethumbdata = '<img src="data:image/jpeg;base64,' + base + '" alt="Embedded Image" />'
        if '1969' in timestamplong: #skip wrong timestamps
            timestamplong = ""
        if creationtimelong == "None":
            creationtimelong = ""
        if pushname == "None":
            pushname = ""
        if mediaurl == "None":
            mediaurl = ""
        if mediamimetype == "None":
            mediamimetype = ""
        if medianame == "None":
            medianame = ""
        if localfileuri == "None":
            localfileuri = ""
        if mediacaption <> "None":
            mediacaption = mediacaption.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        else:
            mediacaption = ""

        # TABLE CELLS: long output
        f_htm_l.write("  <TD>" + messageid + "</TD>\n")
        f_htm_l.write("  <TD>" + keyremotejid + "</TD>\n")
        f_htm_l.write("  <TD>" + keyfromme + "</TD>\n")
        f_htm_l.write("  <TD>" + keyid + "</TD>\n")
        f_htm_l.write('  <TD>' + status + "</TD>\n")
        f_htm_l.write('  <TD>' + data + "</TD>\n")
        f_htm_l.write('  <TD>' + binarydata + "</TD>\n")
        f_htm_l.write('  <TD>' + largethumbdata + "</TD>\n")
        f_htm_l.write("  <TD>" + timestamplong + "</TD>\n")
        f_htm_l.write("  <TD>" + creationtimelong + "</TD>\n")
        f_htm_l.write("  <TD>" + pushname + "</TD>\n")
        f_htm_l.write("  <TD>" + mediaurl + "</TD>\n")
        f_htm_l.write("  <TD>" + mediamimetype + "</TD>\n")
        f_htm_l.write("  <TD>" + mediasize + "</TD>\n")
        f_htm_l.write("  <TD>" + mediadurationseconds + "</TD>\n")
        f_htm_l.write("  <TD>" + medianame + "</TD>\n")
        f_htm_l.write("  <TD>" + localfileuri + "</TD>\n")
        f_htm_l.write("  <TD>" + latitude + "</TD>\n")
        f_htm_l.write("  <TD>" + longitude + "</TD>\n")
        f_htm_l.write("  <TD>" + mediacaption + "</TD>\n")
        f_htm_l.write("</TR>\n")
        
        # TABLE CELLS: short output
        f_htm_s.write("  <TD>" + messageid + "</TD>\n")
        f_htm_s.write("  <TD>" + keyremotejid + "</TD>\n")
        f_htm_s.write('  <TD>' + status + "</TD>\n")
        f_htm_s.write('  <TD>' + data + "</TD>\n")
        f_htm_s.write('  <TD>' + binarydata + "</TD>\n")
        f_htm_s.write("  <TD>" + timestamplong + "</TD>\n")
        f_htm_s.write("  <TD>" + creationtimelong + "</TD>\n")
        f_htm_s.write("  <TD>" + pushname + "</TD>\n")
        f_htm_s.write("</TR>\n")
    f_htm_l.close()
    f_htm_s.close()

  
#write html footer    
for keyremotejid in keyremotejids:
    filename_l = str(keyremotejid[0]) + ".htm"
    filename_s = str(keyremotejid[0]) + "_short.htm"
    f_htm_l = open(filename_l,'ab')
    f_htm_s = open(filename_s,'ab')
    f_htm_l.write("\n</tbody>\n</TABLE>\n</BODY>\n</HTML>")
    f_htm_s.write("\n</tbody>\n</TABLE>\n</BODY>\n</HTML>")
    f_htm_l.close()
    f_htm_s.close()

# ************************ CREATE FOLDERS AND MOVE DATA ************************

#short report with less columns
dst_s_folder = "html_short"

if os.path.exists('./' + dst_s_folder) == True:
    shutil.rmtree(dst_s_folder, ignore_errors=True)
else:
    os.mkdir(dst_s_folder)
for htm_file in os.listdir(os.getcwd()):
    if str(htm_file).endswith('_short.htm'):
        src_file = os.path.join(os.getcwd(), htm_file)
        dst_file = os.path.join(dst_s_folder, htm_file)
        shutil.move(src_file, dst_file)


#download javascript library
try:
    if os.path.exists('./sorttable.js'):
        shutil.copy('sorttable.js', dst_s_folder)
    else:
        try:
            response = urllib2.urlopen("http://www.kryogenix.org/code/browser/sorttable/sorttable.js", timeout = 5)
            content  = response.read()
            f_js = open( "sorttable.js", 'w' )
            f_js.write(content)
            f_js.close()
            shutil.copy('sorttable.js', dst_s_folder)
        except:
            print "Download sorttable.js from:\nhttp://freepages.genealogy.rootsweb.ancestry.com/~gearyfamily/expression-web/sort-table.html"
except:
    pass

#short report with basic columns
dst_s_folder = "html_full"

if os.path.exists('./' + dst_s_folder) == True:
    shutil.rmtree(dst_s_folder, ignore_errors=True)
else:
    os.mkdir(dst_s_folder)
for htm_file in os.listdir(os.getcwd()):
    if str(htm_file).endswith('.htm'):
        src_file = os.path.join(os.getcwd(), htm_file)
        dst_file = os.path.join(dst_s_folder, htm_file)
        shutil.move(src_file, dst_file)
    elif str(htm_file).endswith('.js'):
        src_file = os.path.join(os.getcwd(), htm_file)
        dst_file = os.path.join(dst_s_folder, htm_file)
        shutil.move(src_file, dst_file)


#embdedded pictures: move pictures to a different folder
dst_s_folder = "thumbnails"

os.mkdir(dst_s_folder)
for thumb in os.listdir(os.getcwd()):
    if str(thumb).endswith('.jpg'):
        src_file = os.path.join(os.getcwd(), thumb)
        dst_file = os.path.join(dst_s_folder, thumb)
        shutil.move(src_file, dst_file)
        
#CSV folder
os.mkdir('csv')
shutil.move(f_csv_name, './csv')        

# ************************ STATS ************************
print "\n\nDone!\n"
print "The output files have been saved to %s" % os.getcwd()
print "\n[When importing %s to Excel\nset the origin file to 65001: Unicode (UTF-8)]\n" % f_csv_name

end_time = datetime.now()
print "\nScript started : " + str(start_time)
print "Script finished: " + str(end_time)
print('Duration       : {}'.format(end_time - start_time))