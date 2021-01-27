#!/usr/bin/env python3
import sys
import io
import csv
import binascii
import datetime
import struct
import argparse

csv.field_size_limit(sys.maxsize)
# https://github.com/mandiant/ShimCacheParser/blob/master/ShimCacheParser.py
def convert_filetime(dwLowDateTime, dwHighDateTime):
    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time/10)
    except:
        return None

#
def parse_file(infile,outfile=None):
    with open(infile) as f:
        reader = csv.DictReader(f,delimiter=',')
        for row in reader:
            try:
                data = bytearray.fromhex(row['data'])
                for x in range(len(data)):
                    if data[x:x+4] == b'10ts':
                        ceDataSize = int.from_bytes(data[x+8:x+10],'little')
                        cePathSize = int.from_bytes(data[x+12:x+14],'little')
                        pathOffset = x+14
                        dateOffset = pathOffset+cePathSize+10
                        path = io.BytesIO(data[pathOffset:pathOffset+cePathSize]).read().decode('utf-16le','replace')#.encode('utf-8')
                        lowDatetime, highDatetime = struct.unpack("<LL",data[dateOffset:dateOffset+8])
                        lastModified = convert_filetime(lowDatetime,highDatetime)
                        if outfile:
                            with open(outfile,'a') as f2:
                                writer = csv.writer(f2)
                                writer.writerow([row['host_hostname'],lastModified,path])
                        else:
                            print('\t'.join([row['host_hostname'],str(lastModified),path]))
            except:
                pass

if __name__ == '__main__':
   parser = argparse.ArgumentParser(description="Parse AppCompatCache entries from osquery results. Run SELECT * FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' on all systems, export to csv, and feed.")
   parser.add_argument("-o",metavar="FILE", help="Write output to a CSV file")
   parser.add_argument("file",metavar="FILE", help="osquery CSV results")
   args = parser.parse_args()
   parse_file(args.file, outfile=args.o)
