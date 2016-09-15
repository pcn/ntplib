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


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTPControlAssociation(object):

    def __init__(self):
        pass

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
        "readstat" : 1
        "readvar"  : 2
    }

    def __init__(self, version=2, opcode="readstat", sequence=1):
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
        self.opcode = opcode
        self.sequence = sequence
        self.status = 0
        self.association_id = 0
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
                 self.more_bit << 5 | NTPControlPacket._OPCODES[self.opcode]),
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
            # Length of the
            self.header_len = struct.calcsize(NTPControlPacket._PACKET_FORMAT)
            unpacked = struct.unpack(NTPControlPacket._PACKET_FORMAT,
                data[0:self.header_len])
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
        self.leap = unpacked[3] >> 14 & 0x1  # only use the true/false part, don't got into more detail
        self.clocksource = unpacked[3] >> 8 & 0x1f  # 6 bit mask
        self.system_event_counter = unpacked[3] >> 4 & 0xf
        self.system_event_code = unpacked[3] & 0xf  # End first ushort

        self.association_id = unpacked[4]
        self.offset = unpacked[5]
        self.count = unpacked[6]

        self.association_peer_status = list()
        # XXX wrong step -doing  this in chars instead of bytes or whatever
        # also need to capture The item (4 bytes) as well as the status at each step.
        # I don't think I'm really getting either right now.
        for offset in range(self.header_len, len(data), 4):
            assoc = data[offset:offset+4]
            nca = NTPControlAssociation()
            nca.decode(assoc)
            self.association_peer_status.append(nca)



class NTPControlClient(object):
    """NTP client session."""

    def __init__(self):
        """Constructor."""
        pass

    def request(self, host, version=2, port='ntp', timeout=5):
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
            query_packet = NTPControlPacket()

            # send the request
            s.sendto(query_packet.to_data(), sockaddr)

            # wait for the response - check the source address
            src_addr = None,
            while src_addr[0] != sockaddr[0]:
                response_packet, src_addr = s.recvfrom(256)

            # build the destination timestamp
            dest_timestamp = system_to_ntp_time(time.time())
        except socket.timeout:
            raise NTPException("No response received from %s." % host)
        finally:
            s.close()

        # construct corresponding statistics
        ncp = NTPControlPacket()
        ncp.from_data(response_packet)
        return ncp


def testme():
    ncc = NTPControlClient()
    ncp = ncc.request('127.0.0.1')
    return ncp
