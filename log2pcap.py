import sys
import time
import types
import binascii

#main
if __name__ == '__main__':

    ###pcap header
    """
    guint32 magic_number;   /* magic number */
    guint16 version_major;  /* major version number */
    guint16 version_minor;  /* minor version number */
    gint32  thiszone;       /* GMT to local correction */
    guint32 sigfigs;        /* accuracy of timestamps */
    guint32 snaplen;        /* max length of captured packets, in octets */
    guint32 network;        /* data link type */
    """
    h=[]
    #magic number
    h+=[0xd4, 0xc3, 0xb2, 0xa1]
    #version major
    h+=[0x02, 0x00]
    #version minor
    h+=[0x04, 0x00]
    #thiszone
    h+=[0,0,0,0]
    #sigfigs
    h+=[0,0,0,0]
    #snaplen
    h+=[0xff,0xff,0,0]
    #data link type
    h+=[0x01,0,0,0]
    h_byte=bytes(h)

    ###packet
    fin=open("input.txt", "r")
    fin_content=fin.read().split()
    #print(fin_content)
    
    o=[]
    pktlen=0
    for a in fin_content:
        o.append(int(a, 16))
        pktlen+=1
        if pktlen == 200:
            break
    pktlen-=2
    fin.close()
    #print(o)
    
    o_byte=bytes(o)
    #print(o_byte)

    ###packet header
    """
    guint32 ts_sec;         /* timestamp seconds */
    guint32 ts_usec;        /* timestamp microseconds */
    guint32 incl_len;       /* number of octets of packet saved in file */
    guint32 orig_len;       /* actual length of packet */
    """
    ph=[]
    #ts_sec(fix)
    ph+=[0x3a,0xe0,0xc3,0x57]
    #ts_usec(fix)
    ph+=[0xc8,0x87,0x04,0x00]
    #incl_len
    ph+=[int(pktlen%255),int(pktlen/255),0,0]
    #orig_len
    ph+=[int(pktlen%255),int(pktlen/255),0,0]
    ph_byte=bytes(ph)




    ###write to file
    with open("output.pcap", "wb") as fout:
        fout.write(h_byte)
        fout.write(ph_byte)
        fout.write(o_byte)

    print("FINISHED")
