#!/usr/bin/env python

## purpose: list and extract content of Terminal Reality POD archives.
## copyright: Jan Sperling <ghoostkilla at web dot de>, 2017.
## license: GPLv3+, http://www.gnu.org/licenses/gpl-3.0.html
## author: Jan Sperling <ghoostkilla at web dot de>, 2017.

import sys
import os
import struct
import fnmatch
import argparse
import zlib
from datetime import datetime
from io import BytesIO

class POD:
    ## POD/EPD archive structure
    #
    # POD1 (has no magic)
    # 0x00  header      84 bytes
    # 0x54  index       40 bytes for each entry
    #       data        starts at first file offset
    #
    # POD2
    # 0x00  header      96 bytes
    # 0x60  index       20 bytes for each entry
    #       data        starts at first file offset
    #
    # POD3
    # 0x00  header      288 bytes
    # 0x120 data        starts at first file offset
    #       index       20 bytes for each entry
    #       path table  after the index comes the path table
    #
    # POD4
    # 0x00  header       288 bytes
    # 0x120 data         starts at first file offset
    #       index        28 bytes for each entry 
    #       path table  after the index comes the path table
    #
    # POD5
    # 0x00  header      368 bytes
    # 0x170 data        starts at first file offset
    #       index       28 bytes for each entry 
    #       path table  after the index comes the path table
    #
    # POD6
    # 0x00  header      20 bytes
    # 0x14  data        starts at first file offset
    #       index       24 bytes for each entry
    #       path table  after the index comes the path table
    #
    # EPD / Enhanced POD magic dtxe
    # 0x00  header      272 bytes
    # 0x110 index       80 bytes for each entry
    #       data        starts at first file offset
    #       path table  after the index comes the path table
    #

    ##Header fields
    # Minumim fields for all versions and EPD
    magic = ""
    file_count = None
    index_offset = None
    comment = None
    # EPD and POD6 field only
    version = None
    # Present in EPD and POD2+
    checksum = None
    # Present in POD2+
    audit_file_count = None
    # Present in POD3+
    # 4 Unknown fields
    revision = None
    priority = None
    author = None
    copyright = None
    size_index = None
    # Only in POD5 present
    next_pod_file = None
    #Dict for all file entries
    file_tree = None

    def __init__(self, pod_file=None, parse_only_header=False):
        self.index = None
        self.pod_file = pod_file
        if self.pod_file:
            self.parse_header()
        if not parse_only_header:
            self.parse_file_table()

    def __len__(self):
        if self.file_count is None:
            parse_header()
        return self.file_count

    def __iter__(self):
        if not isinstance(self.file_tree, dict):
            self.file_tree = {}
            self.parse_file_table()
        for file_name in self.file_tree:
            yield file_name, self.file_tree[file_name]

    def _read_uint(self, stream):
        UNSIGNED_INT_LEN = 4
        dword = stream.read(UNSIGNED_INT_LEN)
        if len(dword) != UNSIGNED_INT_LEN:
             raise IOError(2, "unexpected end of file")
        return struct.unpack("I", dword)[0]

    def _get_c_string(self, string):
        return string.decode("ascii").split('\x00')[0]

    def parse_header(self):
        """
        Parse the POD archive header
        """
        COMMENT_LENGTH_POD  =  80 #0x50
        COMMENT_LENGTH_EPD  = 256 #0x100
        AUTHOR_LENGTH       =  80 #0x50
        COPYRIGHT_LENGTH    =  80 #0x50
        NEXT_ARCHIVE_LENGTH =  80 #0x50

        with open(self.pod_file, "rb") as pod_file:
            self.magic = pod_file.read(4).decode("ascii")

            #EPD
            if self.magic == "dtxe":
                # struct EPD_header { 272 bytes
                #     char   magic[4]; // always dtxe
                #     char   comment[256]; // 0x100
                #     uint32 file_count;
                #     uint32 version;
                #     uint32 checksum;
                # }
                self.magic == "EPD"
                self.comment      = self._get_c_string(pod_file.read(COMMENT_LENGTH_EPD))
                self.file_count   = self._read_uint(pod_file)
                self.version      = self._read_uint(pod_file)
                self.checksum     = self._read_uint(pod_file)
                self.index_offset = pod_file.tell()

            elif self.magic == "POD2":
                # struct POD2_header { // 96 bytes
                #     char   magic[4]; // always POD2
                #     uint32 checksum;
                #     char   comment[80]; // 0x50
                #     uint32 file_count;
                #     uint32 audit_file_count;
                # }
                self.checksum          = self._read_uint(pod_file)
                self.comment          = self._get_c_string(pod_file.read(COMMENT_LENGTH_POD))
                self.file_count       = self._read_uint(pod_file)
                self.audit_file_count = self._read_uint(pod_file)
                self.index_offset     = pod_file.tell()
    
            elif self.magic == "POD3" or self.magic == "POD4" or self.magic == "POD5":
                # struct POD3+_header { // 288 bytes POD3/4 / 368 bytes POD5
                #     char   magic[4]; // always POD3/POD4/POD5
                #     uint32 checksum;
                #     char   comment[80]; // 0x50
                #     uint32 file_count;
                #     uint32 audit_file_count;
                #     uint32 revision;
                #     uint32 priority;
                #     char   author[80]; // 0x50
                #     char   copyright[80]; // 0x50
                #     uint32 index_offset;
                #     uint32 unknown10C;
                #     uint32 size_index;
                #     uint32 unknown114;
                #     uint32 unknown118;
                #     uint32 unknown11C;
                #     char   next_pod_file[80]; // 0x50 // POD5 only
                # }
                self.checksum         = self._read_uint(pod_file)
                self.comment          = self._get_c_string(pod_file.read(COMMENT_LENGTH_POD))
                self.file_count       = self._read_uint(pod_file)
                self.audit_file_count = self._read_uint(pod_file)
                self.revision         = self._read_uint(pod_file)
                self.priority         = self._read_uint(pod_file)
                self.author           = self._get_c_string(pod_file.read(AUTHOR_LENGTH))
                self.copyright        = self._get_c_string(pod_file.read(COPYRIGHT_LENGTH))
                self.index_offset     = self._read_uint(pod_file)
                self._read_uint(pod_file) # skip unknown field9 at offset 0x10C
                self.size_index   = self._read_uint(pod_file)
                self._read_uint(pod_file) # skip unknown fieldB at offset 0x114
                self._read_uint(pod_file) # skip unknown fieldC at offset 0x118
                self._read_uint(pod_file) # skip unknown fieldD at offset 0x11C

                if self.magic == "POD5":
                    self.next_pod_file = self._get_c_string(arc.read(NEXT_ARCHIVE_LENGTH))
            elif self.magic == "POD6":
                # struct POD6_header { // 20 bytes POD6
                #     char magic[4];   // always POD6
                #     uint32 file_count;
                #     uint32 version;
                #     uint32 index_offset;
                #     uint32 size_index;
                # }
                self.file_count        = self._read_uint(pod_file)
                self.version           = self._read_uint(pod_file)
                self.index_offset      = self._read_uint(pod_file)
                self.size_index        = self._read_uint(pod_file)
                pod_file.seek(self.index_offset);
            else:
                # struct POD1_header { // 84 bytes
                #     uint32 file_count;
                #     char   comment[80]; // 0x50
                # }
                self.magic = "POD1"
                pod_file.seek(0)
                self.file_count   = self._read_uint(pod_file)
                #self.comment      = self._get_c_string(pod_file.read(COMMENT_LENGTH_POD))
                self.comment      = pod_file.read(COMMENT_LENGTH_POD)
                print("1: %s;" % self.comment)
                self.comment      = self._get_c_string(self.comment)
                print("2: %s;" % self.comment)
                self.index_offset = pod_file.tell()

    def _metadata_struct(self):
        file_metadata = {
            # Minumim imetadata for all versions and EPD
            "name" : None,
            "size" : None,
            "offset" : None,
            # Present in EPD and POD2+
            "timestamp" : None,
            "checksum"  : None,
            # Present in POD2+
            "path_offset" : None,
            "size" : None,
            # Present in POD5+
            "uncompressed_size" : None,
            "compression_level" : 0,
            # Present in POD6
            "flags": None,
            "zero": 0 }
        return file_metadata

    def parse_file_table(self):
        """
        Parse the file table of the POD archive and populates the file directory tree
        """
        if not isinstance(self.file_tree, dict):
            self.file_tree = {}

        self.file_tree.clear()

        if self.magic == "POD1":
            DIR_ENTRY_SIZE = 40
        if self.magic == "EPD":
            DIR_ENTRY_SIZE = 80
        elif self.magic == "POD2" or self.magic == "POD3":
            DIR_ENTRY_SIZE = 20
        elif self.magic == "POD6":
            DIR_ENTRY_SIZE = 24
        else:
            DIR_ENTRY_SIZE = 28

        FILE_NAME_LENGTH      = 256 #0x100
        FILE_NAME_LENGTH_EPD  =  64 #0x40
        FILE_NAME_LENGTH_POD1 =  32 #0x20

        with open(self.pod_file, "rb") as pod_file:
            pod_file.seek(self.index_offset)

            for index in range(0, self.file_count):

                metadata = self._metadata_struct()

                if self.magic == "POD1":
                    # struct POD1_file { // 40 bytes
                    #     char   file_name[32]; // Zero terminated string // 0x20
                    #     uint32 file_size;
                    #     uint32 file_offset;
                    # }
                    file_name                     = self._get_c_string(pod_file.read(FILE_NAME_LENGTH_POD1))
                    metadata["size"]              = self._read_uint(pod_file)
                    metadata["offset"]            = self._read_uint(pod_file)
                    metadata["uncompressed_size"] = metadata["size"]

                elif self.magic == "EPD":
                    # struct EPD_file { // 80 bytes
                    #     char   file_name[64]; // Zero terminated string // 0x40
                    #     uint32 file_size;
                    #     uint32 file_offset;
                    #     uint32 file_timestamp;
                    #     uint32 file_checksum;
                    # }
                    file_name                     = self._get_c_string(pod_file.read(FILE_NAME_LENGTH_EPD))
                    metadata["size"]              = self._read_uint(pod_file)
                    metadata["offset"]            = self._read_uint(pod_file)
                    metadata["timestamp"]         = self._read_uint(pod_file)
                    metadata["checksum"]          = self._read_uint(pod_file)
                    metadata["uncompressed_size"] = metadata["size"]
                elif self.magic == "POD6":
                    # struct POD6_file { // 24 bytes POD6
                    #     uint32 file_path_offset;
                    #     uint32 file_size;
                    #     uint32 file_offset;
                    #     uint32 file_uncompressed_size;
                    #     uint32 file_flags;
                    #     uint32 file_zero;
                    # }
                    # char file_name[256]; // Zero terminated string // 0x100
                    # Seek to the start of the index entry
                    pod_file.seek(self.index_offset + (index * DIR_ENTRY_SIZE))
                    metadata["path_offset"]       = self._read_uint(pod_file)
                    metadata["size"]              = self._read_uint(pod_file)
                    metadata["offset"]            = self._read_uint(pod_file)
                    metadata["uncompressed_size"] = self._read_uint(pod_file)
                    metadata["flags"]             = self._read_uint(pod_file)
                    #metadata["compression_level"] = metadata["flags"]
                    metadata["zero"]              = self._read_uint(pod_file)
                    #metadata["timestamp"] = metadata["zero"]
                    #metadata["checksum"] = metadata["zero"]
                    # get filename from name table
                    # Seek to the file_name entry
                    pod_file.seek(self.index_offset + (self.file_count * DIR_ENTRY_SIZE) + metadata["path_offset"])
                    file_name = self._get_c_string(pod_file.read(FILE_NAME_LENGTH))

                    if metadata["size"] != metadata["uncompressed_size"] and not (metadata["flags"] & 8):

                        raise Warning("Found compressed and uncompressed size mismatch for file %s" % file_name)

                else:
                    # struct POD2+_file { // 20 bytes POD2/3 / 28 POD4+
                    #     uint32 file_path_offset;
                    #     uint32 file_size; // POD4+ this is the compressed size
                    #     uint32 file_offset;
                    #     uint32 file_uncompressed_size; // POD4+ only
                    #     uint32 file_compression_level; // POD4+ only
                    #     uint32 file_timestamp;
                    #     uint32 file_checksum;
                    # }
                    # char   file_name[256]; // Zero terminated string // 0x100
                    # Seek to the start if the index entry
                    pod_file.seek(self.index_offset + (index * DIR_ENTRY_SIZE))
                    metadata["path_offset"] = self._read_uint(pod_file)
                    metadata["size"]        = self._read_uint(pod_file)
                    metadata["offset"]      = self._read_uint(pod_file)
                    if self.magic == "POD4" or self.magic == "POD5":
                        metadata["uncompressed_size"] = self._read_uint(pod_file)
                        metadata["compression_level"] = self._read_uint(pod_file)
                    else:
                        metadata["uncompressed_size"] = metadata["size"]
                    metadata["timestamp"]   = self._read_uint(pod_file)
                    metadata["checksum"]    = self._read_uint(pod_file)

                    # get filename from name table
                    # Seek to the file_name entry
                    pod_file.seek(self.index_offset + (self.file_count * DIR_ENTRY_SIZE) + metadata["path_offset"])
                    file_name = self._get_c_string(pod_file.read(FILE_NAME_LENGTH))

                    if metadata["size"] != metadata["uncompressed_size"] and metadata["compression_level"] == 0:

                        raise Warning("Found compressed and uncompressed size mismatch for file %s" % file_name)

                if os.path.sep != "\\":
                    file_name = file_name.replace("\\",os.path.sep)

                self.file_tree[file_name] = metadata


    def read_file(self, file_name, uncompress=False):
        """
        Reads the data from a single file inside the POD archive and returns a file-like object
        """
        with open(self.pod_file, "rb") as pod_file:

            pod_file.seek(self.file_tree[file_name]["offset"])
            data = pod_file.read(self.file_tree[file_name]["size"])
            if uncompress:
                data = self.uncompress(data)
            return BytesIO(data)

    def uncompress(self, data):
        """
        uncompress extracted data
        """
        #TODO compressed files, seems like some sort of zlib raw deflate format(no header)
        raise NotImplementedError("data uncompression is not implemented")
        return data
        pass

    def verify(self, data, checksum):
        """
        verify the data of an file
        """
        #TODO the checksum is not crc32(data)
        raise NotImplementedError("data verification is not implemented")
        pass

def make_parser():
    parser = argparse.ArgumentParser(description="Extract Terminal Reality POD and EPD archive files")

    group = parser.add_mutually_exclusive_group()

    parser.add_argument("file",  help="input POD/EPD file")
    parser.add_argument("dir", help="directory to where the files will be extracted", nargs="?", default=os.getcwd() + "/extract")
    group.add_argument("-l", "--list", help="list files of the POD file", action="store_true")
    group.add_argument("-ll", "--listlong", help="list files of the POD file with size and time stamp", action="store_true")
    group.add_argument("-x", "--extract", help="extract files from the POD file", action="store_true")
    parser.add_argument("-p", "--pattern", help="list or extract files that match the pattern only")

    return parser

def filter_file(file_name, pattern):
    if not pattern:
        True
    return fnmatch.fnmatchcase(file_name, pattern)

def print_header(pod):
    num_files = len(pod)

    print("%20s: %s" % ("POD File", pod.pod_file))
    print("%20s: %s" % ("File Type", pod.magic))
    print("%20s: %s" % ("Version", pod.version))

    print("%20s: %s" % ("Comment", pod.comment))
    if pod.author:
        print("%20s: %s" % ("Author", pod.author))
    if pod.copyright:
        print("%20s: %s" % ("Copyright", pod.copyright))
    if pod.next_pod_file:
        print("%20s: %s" % ("Next File", pod.next_pod_file))

    print("%20s: %s" % ("Index Offset", pod.index_offset))
    if pod.size_index:
        print("%20s: %s" % ("Index Size", pod.size_index))
    if pod.checksum:
        print("%20s: %s" % ("Checksum", pod.checksum))
    print("%20s: %s" % ("Size", os.path.getsize(pod.pod_file)))
    print("%20s: %s" % ("Number of files", num_files))
def list_files(pod, pattern=None, include_details=False):
    for file_name, file_metadata in sorted(pod):
        if pattern and not filter_file(file_name, pattern):
            continue

        if file_metadata["timestamp"]:
            date = datetime.fromtimestamp(file_metadata["timestamp"])
        else:
            date = "n/a"

        if include_details:
            if pod.magic == "POD4" or pod.magic == "POD5":
                print("%s Date:%s Offset:%s Size:%s/%s compression level: %s Checksum: %s" % (file_name, date, file_metadata["offset"], file_metadata["size"], file_metadata["uncompressed_size"], file_metadata["compression_level"], file_metadata["checksum"]))
            else:
                if pod.magic == "POD6":
                    print("%s Date:%s Offset:%s Size:%s/%s Flags: %s" % (file_name, date, file_metadata["offset"], file_metadata["size"], file_metadata["uncompressed_size"], file_metadata["flags"]))
                else: 
                    if pod.magic != "POD1" and pod.magic != "":
                        print("%s Date:%s Offset:%s Size:%s Checksum: %s" % (file_name, date, file_metadata["offset"], file_metadata["size"], file_metadata["checksum"]))
                    else:
                        print("%s Date:%s Offset:%s Size:%s" % (file_name, date, file_metadata["offset"], file_metadata["size"]))

        else:
            print(file_name)

def extract_files(pod, dest_dir, pattern=None):
    for file_name, file_metadata in sorted(pod):
        if pattern and not filter_file(file_name, pattern):
            continue
        out_dir, base_name = os.path.split(file_name)
        out_dir = os.path.join(dest_dir,out_dir)
        full_path = os.path.join(out_dir, base_name)

        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        extract = pod.read_file(file_name)

        with open(full_path, "wb") as out_file:

            if file_metadata["compression_level"] > 0:
                print("%s -> %s (compressed)"% (file_name, full_path))
                #extract = pod.uncompress(extract)
            else:
                print("%s -> %s"% (file_name, full_path))
            out_file.write(extract.read())

        if file_metadata["timestamp"]:
            os.utime(full_path,(file_metadata["timestamp"],file_metadata["timestamp"]))

def main(argv):
    parser = make_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        raise IOError("File not found: " + args.file)

    pod = POD(args.file)

    if args.extract:
        extract_files(pod, args.dir, args.pattern)
    elif args.list or args.listlong:
        list_files(pod, args.pattern, args.listlong)
    else:
        print_header(pod)

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as exc:
        sys.stderr.write("%s\n" % exc)
        sys.exit(1)
