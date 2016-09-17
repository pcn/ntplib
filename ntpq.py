#!/usr/bin/env python


###############################################################################
# ntplib - Python NTP library.
# Copyright (C) 2009 Charles-Francois Natali <neologix@free.fr>
#
# ntplib is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place, Suite 330, Boston, MA 0.1.2-1307 USA
###############################################################################
"""Python NTP library.

Implementation of client-side NTP (RFC-1305), and useful NTP-related
functions.
"""


import datetime
import socket
import struct
import time

import ntplib


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTPControlAssociation(object):

    def __init__(self):
        raise ValueError, "Don't use me"

    def __str__(self):
        return str({ k:v for (k, v) in self.__dict__.items() if not k.startswith('_')})

    def decode(self, data):
        """
        Provided a 2 uchar of data, unpack the first uchar of associationID,
        and the second uchar of association data from that uchar

        test with  e.g. data set to:
        In [161]: struct.pack("!B B", 0b00010100,0b00011010)
        Out[161]: '\x14\x1a'
        """
        unpacked = struct.unpack("!H B B", data)

        self.association_id = unpacked[0]

        self.peer_config = unpacked[1] >> 7 & 0x1
        self.peer_authenable = unpacked[1] >> 6 & 0x1
        self.peer_authentic = unpacked[1] >> 5 & 0x1
        self.peer_reach = unpacked[1] >> 4 & 0x1
        self.reserved = unpacked[1] >> 3 & 0x1
        self.peer_selection = unpacked[1] & 0x7

        self.peer_event_counter = unpacked[2] >> 4 & 0xf
        self.peer_event_code = unpacked[2] & 0xf



class NTPControlPacket(object):
    """NTP control packet class.

    This represents an NTP control packet.
    """

    _PACKET_FORMAT = "!B B H H H H H" #Maybe, maybe not
    """packet format to pack/unpack"""

    _OPCODES = {
        "readstat" : 1,
        "readvar"  : 2
    }

    def __init__(self, version=2, op="readstat", association_id=0, sequence=1):
        """Constructor.

        Parameters:
        version      -- NTP version
        mode         -- packet mode (control, aka 6)
        tx_timestamp -- packet transmit timestamp
        """
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = 6
        """mode"""
        self.response_bit = 0 # request
        self.error_bit = 0
        self.more_bit = 0
        self.opcode = NTPControlPacket._OPCODES[op]
        self.sequence = sequence
        self.status = 0
        self.association_id = association_id
        self.offset = 0
        self.count = 0


    def to_data(self):
        """Convert this NTPControlPacket to a buffer that can be sent over a socket.

        Returns:
        buffer representing this packet

        Raises:
        NTPException -- in case of invalid field
        """
        try:
            packed = struct.pack(
                NTPControlPacket._PACKET_FORMAT,
                (self.leap << 6 | self.version << 3 | self.mode),
                (self.response_bit << 7 | self.error_bit << 6 |
                 self.more_bit << 5 | self.opcode),
                self.sequence,
                self.status,
                self.association_id,
                self.offset,
                self.count)
        except struct.error:
            raise NTPException("Invalid NTP packet fields.")
        return packed

    def from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.

        Parameters:
        data -- buffer payload

        Raises:
        NTPException -- in case of invalid packet format
        """
        try:
            header_len = struct.calcsize(NTPControlPacket._PACKET_FORMAT)
            unpacked = struct.unpack(NTPControlPacket._PACKET_FORMAT,
                data[0:header_len])
        except struct.error:
            raise NTPException("Invalid NTP packet.")

        # header status
        self.leap = unpacked[0] >> 6 & 0x1
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7  # end first uchar

        self.response_bit = unpacked[1] >> 7 & 0x1
        self.error_bit = unpacked[1] >> 6 & 0x1
        self.more_bit = unpacked[1] >> 5 & 0x1
        self.opcode = unpacked[1] & 0x1f  # end second uchar

        self.sequence = unpacked[2]

        # Another status (what do the docs call this?)
        # only use the true/false bit somehow? don't get into more detail
        self.leap = unpacked[3] >> 14 & 0x1
        self.clocksource = unpacked[3] >> 8 & 0x1f  # 6 bit mask
        self.system_event_counter = unpacked[3] >> 4 & 0xf
        self.system_event_code = unpacked[3] & 0xf  # End first ushort

        self.association_id = unpacked[4]
        self.offset = unpacked[5]
        self.count = unpacked[6]

        opcodes_by_number = { v:k for k,v in NTPControlPacket._OPCODES.items() }
        if opcodes_by_number[self.opcode] == "readstat":
            self.decode_readstat(header_len,  data)
        elif opcodes_by_number[self.opcode] == "readvar":
            self.decode_readvar(header_len,  data)

    def decode_readstat(self, header_len, data):
        self.data = list()
        for offset in range(header_len, len(data), 4):
            assoc = data[offset:offset+4]
            association_dict = decode_association(assoc)
            self.data.append(association_dict)

    def decode_readvar(self, header_len, data):
        """From libntpq.h in the ntp distribution:
/* NTP Status codes */
#define NTP_STATUS_INVALID      0
#define NTP_STATUS_FALSETICKER  1
#define NTP_STATUS_EXCESS       2
#define NTP_STATUS_OUTLIER      3
#define NTP_STATUS_CANDIDATE    4
#define NTP_STATUS_SELECTED     5
#define NTP_STATUS_SYSPEER      6
#define NTP_STATUS_PPSPEER      7

        """


        # TODO:  encode data here
        buf = data[header_len:].split(",")
        self.data = dict()
        for d in buf:
            key, val = d.replace("\r\n", "").lstrip().split("=")
            if key in ('rec', 'reftime'):
                int_part, frac_part = map(
                    lambda x: int(x, 16), val.split("."))
                self.data[key] = ntplib.ntp_to_system_time(
                    ntplib._to_time(int_part, frac_part))
            else:
                self.data[key] = val
        # For the equivalent of the 'when' column, in ntpq -c pe
        # I believe that the time.time() minus the 'rec' field will give that.
        self.data['when'] = time.time() - self.data['rec']


class NTPControlClient(object):
    """NTP client session."""

    def __init__(self):
        """Constructor."""
        pass

    def request(self, host, version=2, port='ntp', op="readvar", association_id=0, timeout=5):
        """Query a NTP server.

        Parameters:
        host    -- server name/address
        version -- NTP version to use
        port    -- server port
        timeout -- timeout on socket operations

        Returns:
        NTPStats object ??? XXX
        """
        # lookup server address
        addrinfo = socket.getaddrinfo(host, port)[0]
        family, sockaddr = addrinfo[0], addrinfo[4]

        # create the socket
        s = socket.socket(family, socket.SOCK_DGRAM)

        try:
            s.settimeout(timeout)

            # create the request packet - mode 3 is client
            query_packet = NTPControlPacket(
                op=op, association_id=association_id)

            # send the request
            s.sendto(query_packet.to_data(), sockaddr)

            # wait for the response - check the source address
            src_addr = None,
            # Will there ever be enough control info to need to
            # concat multiple recvfroms()?
            while src_addr[0] != sockaddr[0]:
                response_packet, src_addr = s.recvfrom(512)

            # build the destination timestamp
            dest_timestamp = ntplib.system_to_ntp_time(time.time())
        except socket.timeout:
            raise NTPException("No response received from %s." % host)
        finally:
            s.close()

        ncp = NTPControlPacket()
        ncp.from_data(response_packet)
        return ncp


def composite_associnfo(host="127.0.0.1"):
    """
    returns a list of associations from the host,
    this data is a mixture of the data that is gotten
    from the commands 'ntpq -c pe' and 'ntpq -c as'

    """
    ncc = NTPControlClient()
    ncp = ncc.request(host, op="readstat")
    data = list()
    for assoc in ncp.data:
        readvar_data = ncc.request(
            host, op="readvar", association_id=assoc['association_id'])
        for k, v in assoc.items():
            readvar_data.data[k] = v
        data.append(readvar_data)
    return data

def decode_association(data):
    """
    Provided a 2 uchar of data, unpack the first uchar of associationID,
    and the second uchar of association data from that uchar

    test with  e.g. data set to:
    In [161]: struct.pack("!B B", 0b00010100,0b00011010)
    Out[161]: '\x14\x1a'
    """
    unpacked = struct.unpack("!H B B", data)

    return {
        'association_id' : unpacked[0],

        'peer_config' : unpacked[1] >> 7 & 0x1,
        'peer_authenable' : unpacked[1] >> 6 & 0x1,
        'peer_authentic' : unpacked[1] >> 5 & 0x1,
        'peer_reach' : unpacked[1] >> 4 & 0x1,
        'reserved' : unpacked[1] >> 3 & 0x1,
        'peer_selection' : unpacked[1] & 0x7,

        'peer_event_counter' : unpacked[2] >> 4 & 0xf,
        'peer_event_code' : unpacked[2] & 0xf
    }
