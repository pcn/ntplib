#!/usr/bin/env python

# pragma pylint: disable=bad-whitespace
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
"""Python NTP control client implementation

This emulates the action fo the ntpq library, specifically two of the
read commands, "associations" and "peers".

"""


import datetime
import socket
import struct
import time

import ntplib

NTP_CONTROL_PACKET_FORMAT = "!B B H H H H H" #Maybe, maybe not
"""packet format to pack/unpack"""

NTP_CONTROL_OPCODES = {
    "readstat" : 1,
    "readvar"  : 2
}

# packet format to pack/unpack
CONTROL_PACKET_FORMAT = "!B B H H H H H"


class NTPException(Exception):
    """Exception raised by this module."""
    pass


def composite_assoc_and_peer(host="127.0.0.1"):
    """
    returns a list of associations from the host,
    combined with the peer data.

    This data is a mixture of the data that is gotten
    from the commands 'ntpq -c pe' and 'ntpq -c as'
    """
    # ncc = NTPControlClient()
    # ncp = ncc.request(host, op="readstat")
    data = list()
    ncp_data = ntp_control_request(host, op="readstat")
    for assoc in ncp_data['associations']:
        readvar_data = ntp_control_request(
            host, op="readvar", association_id=assoc['association_id'])
        for k, v in assoc.items():
            readvar_data[k] = v
        data.append(readvar_data)
    return data


def decode_association(data):
    """
    Provided a 2 uchar of data, unpack the first uchar of associationID,
    and the second uchar of association data from that uchar

    test with  e.g. data set to:
    In [161]: struct.pack("!B B", 0b00010100,0b00011010)
    Out[161]: '\x14\x1a'

    This is the data for a single association.
    """
    unpacked = struct.unpack("!H B B", data)

    return {
        'association_id'     : unpacked[0],
        'peer_config'        : unpacked[1] >> 7 & 0x1,
        'peer_authenable'    : unpacked[1] >> 6 & 0x1,
        'peer_authentic'     : unpacked[1] >> 5 & 0x1,
        'peer_reach'         : unpacked[1] >> 4 & 0x1,
        'reserved'           : unpacked[1] >> 3 & 0x1,
        'peer_selection'     : unpacked[1] & 0x7,
        'peer_event_counter' : unpacked[2] >> 4 & 0xf,
        'peer_event_code'    : unpacked[2] & 0xf
    }


def control_data_payload(version=2, op='readstat', association_id=0, sequence=1):
    """Convert the requested arguments into a buffer that can be sent over a socket.
    to an ntp server.

    Returns:
    buffer representing this packet

    Raises:
    NTPException -- in case of invalid field
    """
    leap           = 0       # leap second indicator
    version        = version # protocol version
    mode           = 6       # mode 6 is the control mode
    response_bit   = 0       # request
    error_bit      = 0
    more_bit       = 0
    opcode         = NTP_CONTROL_OPCODES[op]
    sequence       = sequence
    status         = 0
    association_id = association_id
    offset         = 0
    count          = 0
    try:
        packed = struct.pack(
            NTP_CONTROL_PACKET_FORMAT,
            (leap << 6 | version << 3 | mode),
            (response_bit << 7 | error_bit << 6 | more_bit << 5 | opcode),
            sequence,
            status,
            association_id,
            offset,
            count)
        return packed
    except struct.error:
        raise NTPException("Invalid NTP packet fields.")


def ntp_control_request(host, version=2, port='ntp',  # pylint: disable=too-many-arguments,invalid-name
                        op="readvar", association_id=0, timeout=5):
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
    sock = socket.socket(family, socket.SOCK_DGRAM)

    try:
        sock.settimeout(timeout)

        # create a control request packet
        sock.sendto(
            control_data_payload(
                op=op, version=version,
                association_id=association_id),
            sockaddr)

        # wait for the response - check the source address
        src_addr = None,
        while src_addr[0] != sockaddr[0]:
            response_packet, src_addr = sock.recvfrom(512)

        # build the destination timestamp
        # dest_timestamp = ntplib.system_to_ntp_time(time.time())
    except socket.timeout:
        raise NTPException("No response received from %s." % host)
    finally:
        sock.close()

    packet_dict = control_packet_from_data(response_packet)
    return packet_dict


def control_packet_from_data(data):
    """Populate this instance from a NTP packet payload received from
    the network.

    Parameters:
    data -- buffer payload

    Returns:
    dictionary of control packet data.

    Raises:
    NTPException -- in case of invalid packet format
    """

    def decode_readstat(header_len, data, rdata):
        """
        Decodes a readstat request.  Augments rdata with
        association IDs from data
        """
        rdata['associations'] = list()
        for offset in range(header_len, len(data), 4):
            assoc = data[offset:offset+4]
            association_dict = decode_association(assoc)
            rdata['associations'].append(association_dict)
        return rdata

    def decode_readvar(header_len, data, rdata):
        """
        Decodes a redvar request.  Augments rdata dictionary with
        the textual data int he data packet.
        """
        buf = data[header_len:].split(",")
        for field in buf:
            key, val = field.replace("\r\n", "").lstrip().split("=")
            if key in ('rec', 'reftime'):
                int_part, frac_part = [ int(x, 16) for x in val.split(".") ]
                rdata[key] = ntplib.ntp_to_system_time(
                    ntplib._to_time(int_part, frac_part))  # pylint: disable=protected-access
            else:
                rdata[key] = val
        # For the equivalent of the 'when' column, in ntpq -c pe
        # I believe that the time.time() minus the 'rec' field will give that.
        rdata['when'] = time.time() - rdata['rec']
        return rdata

    try:
        header_len = struct.calcsize(CONTROL_PACKET_FORMAT)
        unpacked = struct.unpack(CONTROL_PACKET_FORMAT, data[0:header_len])
    except struct.error:
        raise NTPException("Invalid NTP packet.")

    # header status
    rdata = {
        "leap_header"          : unpacked[0] >> 6 & 0x1,
        "version"              : unpacked[0] >> 3 & 0x7,
        "mode"                 : unpacked[0] & 0x7,  # end first uchar
        "response_bit"         : unpacked[1] >> 7 & 0x1,
        "error_bit"            : unpacked[1] >> 6 & 0x1,
        "more_bit"             : unpacked[1] >> 5 & 0x1,
        "opcode"               : unpacked[1] & 0x1f,  # end second uchar
        "sequence"             : unpacked[2],
        "leap"                 : unpacked[3] >> 14 & 0x1,
        "clocksource"          : unpacked[3] >> 8 & 0x1f,  # 6 bit mask
        "system_event_counter" : unpacked[3] >> 4 & 0xf,
        "system_event_code"    : unpacked[3] & 0xf,  # End first ushort
        "association_id"       : unpacked[4],
        "offset"               : unpacked[5],
        "count"                : unpacked[6]
    }

    opcodes_by_number = { v:k for k,v in NTP_CONTROL_OPCODES.items() }
    if opcodes_by_number[rdata['opcode']] == "readstat":
        return decode_readstat(header_len,  data, rdata)
    elif opcodes_by_number[rdata['opcode']] == "readvar":
        return decode_readvar(header_len,  data, rdata)
