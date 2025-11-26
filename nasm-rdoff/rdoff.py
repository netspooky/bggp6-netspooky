#!/usr/bin/env python3
from enum import IntEnum
from scapy.all import ByteEnumField
from scapy.all import ByteField
from scapy.all import LEIntField
from scapy.all import LEShortEnumField
from scapy.all import LEShortField
from scapy.all import MultipleTypeField
from scapy.all import Packet
from scapy.all import PacketField
from scapy.all import PacketLenField
from scapy.all import PacketListField
from scapy.all import StrFixedLenField
from scapy.all import StrNullField
from scapy.all import XStrLenField
from scapy.all import XStrFixedLenField

# Scapy Fields https://scapy.readthedocs.io/en/latest/api/scapy.fields.html

### SEGMENTS ###################################################################

class RDFSEG(IntEnum):
    # from rdoff/rdoff.c knownsegtypes
    # Only the first 3 seem to be used!
    NULL              = 0
    TEXT              = 1
    DATA              = 2
    object_comment    = 3
    linked_comment    = 4
    loader_comment    = 5
    symbolic_debug    = 6
    line_number_debug = 7

class RDFSEG_TLV(Packet):
    name = "RDFSEG"
    fields_desc = []
    fields_desc.append( LEShortEnumField('type',0, RDFSEG) )
    fields_desc.append( LEShortField('number', 0) )
    fields_desc.append( LEShortField('resrvd', 0) )
    fields_desc.append( LEIntField('length', 0) )
    fields_desc.append( XStrLenField('data', b'' , length_from = lambda pkt: pkt.length))
    def extract_padding(self, p):
        return "", p

class RDFSEGS(Packet):
    name = "RDFSEGS"
    fields_desc = []
    fields_desc.append( PacketListField('rdf_segs', [], RDFSEG_TLV) ) # this returns the records
    def extract_padding(self, p):
        return "", p

### HEADER RECORDS #############################################################

class RDFREC(IntEnum):
    # Record Types, adapted from rdoff/rdoff.h
    GENERIC   = 0
    RELOC     = 1
    IMPORT    = 2
    GLOBAL    = 3
    DLL       = 4
    BSS       = 5
    SEGRELOC  = 6
    FARIMPORT = 7
    MODNAME   = 8  
    COMMON    = 10

# XXX TODO - RDFREC_GENERIC

class RDFREC_RELOC(Packet):
    name = "RDFREC_RELOC" # 1, 6
    fields_desc = []
    fields_desc.append(ByteField('segment', 0))
    fields_desc.append(LEIntField('offset', 0))
    fields_desc.append(ByteField('length', 0))
    fields_desc.append(LEShortField('refseg', 0))

    def extract_padding(self, p):
        return "", p

class RDFREC_IMPORT(Packet):
    name = "RDFREC_IMPORT" # 2, 7
    fields_desc = []
    fields_desc.append(ByteField('flags', 0))
    fields_desc.append(LEShortField('segment', 0))
    fields_desc.append(StrNullField('label',''))

    def extract_padding(self, p):
        return "", p

class RDFREC_GLOBAL(Packet):
    # EXPORT = GLOBAL = PUBLIC
    # struct from rdoff/symtab.c
    # symtabFind uses this symbol which matches up with this class
    # typedef struct {
    #     char *name;
    #     int segment;
    #     int32_t offset;
    #     int32_t flags;
    # } symtabEnt;
    # The offset refers to the start of the segment data
    name = "RDFREC_GLOBAL" # 3
    fields_desc = []
    fields_desc.append(ByteField('flags', 0))
    fields_desc.append(ByteField('segment', 0))
    fields_desc.append(LEIntField('offset', 0))
    fields_desc.append(StrNullField('label',''))

    def extract_padding(self, p):
        return "", p

class RDFREC_DLL(Packet):
    name = "RDFREC_DLL" # 4
    fields_desc = []
    fields_desc.append(StrNullField('libname',''))

    def extract_padding(self, p):
        return "", p

class RDFREC_BSS(Packet):
    name = "RDFREC_BSS" # 5
    fields_desc = []
    fields_desc.append(LEIntField('bss_size', 0))

    def extract_padding(self, p):
        return "", p

class RDFREC_MODNAME(Packet):
    name = "RDFREC_MODNAME" # 8
    fields_desc = []
    fields_desc.append(StrNullField('modname',''))

    def extract_padding(self, p):
        return "", p

# XXX TODO - RDFREC_COMMON

class RDFRECS(Packet):
    name = "RDFRECS"
    fields_desc = []
    fields_desc.append( ByteEnumField('type',0, RDFREC) )
    fields_desc.append( ByteField('length', 0) )
    fields_desc.append( 
            MultipleTypeField( [ 
                      ( PacketField('value', None, RDFREC_RELOC),   lambda pkt: pkt.type == RDFREC.RELOC ),     # 1
                      ( PacketField('value', None, RDFREC_IMPORT),  lambda pkt: pkt.type == RDFREC.IMPORT ),    # 2
                      ( PacketField('value', None, RDFREC_GLOBAL),  lambda pkt: pkt.type == RDFREC.GLOBAL ),    # 3
                      ( PacketField('value', None, RDFREC_DLL),     lambda pkt: pkt.type == RDFREC.DLL ),       # 4
                      ( PacketField('value', None, RDFREC_BSS),     lambda pkt: pkt.type == RDFREC.BSS ),       # 5
                      ( PacketField('value', None, RDFREC_RELOC),   lambda pkt: pkt.type == RDFREC.SEGRELOC ),  # 6
                      ( PacketField('value', None, RDFREC_IMPORT),  lambda pkt: pkt.type == RDFREC.FARIMPORT ), # 7
                      ( PacketField('value', None, RDFREC_MODNAME), lambda pkt: pkt.type == RDFREC.MODNAME ),  # 8
                                ],
                        XStrFixedLenField('value', b'', length_from=lambda pkt: pkt.length) # Default value
                      ) )
    def extract_padding(self, p):
        return "", p

class RDFHDR(Packet):
    name = "Header"
    fields_desc = []
    fields_desc.append( PacketListField('hdr_recs', [], RDFRECS) ) # this returns the records

    def extract_padding(self, p):
        return "", p

### Main Class #################################################################

class RDOFF(Packet):
    name = 'RDOFF'
    fields_desc = []
    fields_desc.append(StrFixedLenField('magic', 'RDOFF2', length=6))
    fields_desc.append(LEIntField('obj_len', 0)) # length of everything after this point, need to add the 4 byte hdr_len to this

    fields_desc.append(LEIntField('hdr_len', 0)) # length of header
    fields_desc.append(PacketLenField("hdr", None, RDFHDR, length_from=lambda pkt: pkt.hdr_len))

    fields_desc.append(PacketField("segs", None, RDFSEGS))

### TESTS ######################################################################

def test1_RDF():
    # This test parses the original RDF file that nasm created 6.rdf
    buf =  '52 44 4f 46 46 32 40 00 00 00'
    buf += '11 00 00 00 02 09 00 03 00 5f 6d 61 69 6e 00 05 04 01 00 00 00'
    buf += '01 00 00 00 00 00 0c 00 00 00 b8 3c 00 00 00 bf 06 00 00 00 0f 05 02 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    mybuf = bytes.fromhex(buf)

    mypkt = RDOFF(mybuf)
    Packet.show2(mypkt)

def test2_build():
    # this creates the original RDF file using the scapy library
    # 3dc28af645b3b3324691aea8236f2459b22532839e2a4645a0de49d1acb47e5e  6.rdf
    # 3dc28af645b3b3324691aea8236f2459b22532839e2a4645a0de49d1acb47e5e  clone.rdf

    rdf_hdr_1 = RDFREC_IMPORT(segment=3,label="_main")
    rdf_hdr_2 = RDFREC_BSS(bss_size=1)

    rdf_tlv1 = RDFRECS(type=RDFREC.IMPORT, length=len(rdf_hdr_1), value=rdf_hdr_1)
    rdf_tlv2 = RDFRECS(type=RDFREC.BSS, length=len(rdf_hdr_2), value=rdf_hdr_2)

    rdf_hdr = RDFHDR()
    rdf_hdr.hdr_recs.append(rdf_tlv1)
    rdf_hdr.hdr_recs.append(rdf_tlv2)

    mycode = bytes.fromhex("b83c000000bf060000000f05")

    rdf_text = RDFSEG_TLV(type=RDFSEG.TEXT, length=12, data=mycode)
    rdf_data = RDFSEG_TLV(type=RDFSEG.DATA, number=1, length=1, data=b"\x00")
    rdf_segs = RDFSEGS()
    rdf_segs.rdf_segs.append(rdf_text)
    rdf_segs.rdf_segs.append(rdf_data)

    print(len(rdf_hdr))
    print(len(rdf_segs))

    padding = b"\x00" * 10
    obj_len = len(rdf_hdr) + len(rdf_segs) + len(padding) + 4 # the +4 is for the hdr_len for now

    rdoff = RDOFF(hdr_len=len(rdf_hdr),hdr=rdf_hdr, segs=rdf_segs, obj_len=obj_len) 
    rdoff_pad = rdoff / padding

    rdoff_pad.show2()

    with open("clone.rdf","wb") as f:
        f.write(bytes(rdoff_pad))
        f.close()

def test3_global():
    # This generates an RDF with an Global/Export/Public header type that can be loaded by rdx called global.rdf
    # It doesn't use any tricks to make it small
    # df5a07fb3400e95d4c68cb36a10451f15bd1ca536b50993709d7a534a3b3f4a6  global.rdf
    # (venv-2025) 2025-11-24 14:10:16 ~/projects/binarygolf/bggp6 
    # ▶ xxd global.rdf 
    # 00000000: 5244 4f46 4632 4300 0000 1400 0000 030c  RDOFF2C.........
    # 00000010: 0000 0000 0000 5f6d 6169 6e00 0504 0100  ......_main.....
    # 00000020: 0000 0100 0000 0000 0c00 0000 b83c 0000  .............<..
    # 00000030: 00bf 0600 0000 0f05 0200 0100 0000 0100  ................
    # 00000040: 0000 6600 0000 0000 0000 0000 00         ..f..........

    # Setting up the header - a GLOBAL, which points to the code section
    hdr_global = RDFREC_GLOBAL(segment=0,label="_main")
    # This one BSS segment is also needed
    hdr_bss = RDFREC_BSS(bss_size=1)

    # Now we construct the header and add our records to the list
    rdf_hdr = RDFHDR()
    rdf_hdr.hdr_recs.append(RDFRECS(type=RDFREC.GLOBAL, length=len(hdr_global), value=hdr_global))
    rdf_hdr.hdr_recs.append(RDFRECS(type=RDFREC.BSS, length=len(hdr_bss), value=hdr_bss))

    # This is the code we want to run, here it just exits 6 using a syscall
    mycode = bytes.fromhex("b83c000000bf060000000f05")

    # construct the segments
    rdf_segs = RDFSEGS()
    rdf_segs.rdf_segs.append(RDFSEG_TLV(type=RDFSEG.TEXT, length=len(mycode), data=mycode))
    rdf_segs.rdf_segs.append(RDFSEG_TLV(type=RDFSEG.DATA, number=1, length=1, data=b"\x66"))

    # This padding was added by nasm, not sure if it was intentional but we account for it anyways
    padding = b"\x00" * 10 # unknown usage
    obj_len = len(rdf_hdr) + len(rdf_segs) + len(padding) + 4 # the +4 is for the hdr_len for now

    # Now to initialize the entire file buffer and add our segments, appending the padding
    rdoff = RDOFF(hdr_len=len(rdf_hdr),hdr=rdf_hdr, segs=rdf_segs, obj_len=obj_len) / padding
    
    rdoff.show2() # show the dissected fields

    with open("global.rdf","wb") as f:
        f.write(bytes(rdoff))
        f.close()

if __name__ == "__main__":
    #test1_RDF()
    #test2_build()
    test3_global()
