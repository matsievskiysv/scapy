# scapy.contrib.description = CFM
# scapy.contrib.status = loads

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

"""
    CFM EOAM
    ~~~~~~~~

    :author:    Sergey Matsievskiy, matsievskiysv@gmail.com
    :license:   GPLv2

        This module is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This module is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :description:

        This module provides Scapy layers for the CFM EOAM protocol.

        normative references:
          - ITU-T Rec. G.8013/Y.1731 (08/2019) - Operation, administration and
            maintenance (OAM) functions and mechanisms for Ethernet-based
            networks
          - ITU-T Rec. G.8031/Y.1342 (01/2015) - Ethernet linear protection
            switching
          - ITU-T Rec. G.8032/Y.1344 (02/2022) - Ethernet ring protection
            switching

Fields table (csv):
,1,3,2,5,4,33,35,37,39,40,41(0),41(1),43,42,45,47,46,49,48,51,50,52,55,54,53,32
mel,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+
version,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+
opcode,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+
flags,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+
tlv_offset,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+
seq_num,+,+,+,,,,,+,,,,,,,,,,,,,,,,,,
trans_id,,,,+,+,,,,,,,,,,,,,,,,,,,,,
oui,,,,,,,,,,,+,+,,,,,,+,+,+,+,,,,,
subopcode,,,,,,,,,,,+,+,,,,,,+,+,+,+,,,,,+
mep_id,+,,,,,,,,,,,+,,,,,,,,,,,,,,
meg_id,+,,,,,,,,,,,,,,,,,,,,,,,,,
src_mep_id,,,,,,,,,,,,,,,,,,,,,,,+,+,+,
rsv_mep_id,,,,,,,,,,,,,,,,,,,,,,,+,+,+,
test id,,,,,,,,,,,,,,,,,,,,,,,+,+,+,
txfcf,+,,,,,,,,,,,,+,+,,,,,,,,,+,+,+,
rxfcb,+,,,,,,,,,,,,,,,,,,,,,,,,,
rxfcf,,,,,,,,,,,,,+,+,,,,,,,,,,,,
txfcb,+,,,,,,,,,,,,+,+,,,,,,,,,+,+,,
resv,+,,,,,,,,,,,,,,,,,,,,,,,,+,
ttl,,,,+,+,,,,,,,,,,,,,,,,,,,,,
orig_mac,,,,+,,,,,,,,,,,,,,,,,,,,,,
targ_mac,,,,+,,,,,,,,,,,,,,,,,,,,,,
relay_act,,,,,+,,,,,,,,,,,,,,,,,,,,,
txtsf,,,,,,,,,,,,,,,+,+,+,,,,,,,,,
rxtsf,,,,,,,,,,,,,,,+,+,+,,,,,,,,,
txtsb,,,,,,,,,,,,,,,,+,+,,,,,,,,,
rxtsb,,,,,,,,,,,,,,,,+,+,,,,,,,,,
expct_dur,,,,,,,,,,,,+,,,,,,,,,,,,,,
nom_bdw,,,,,,,,,,,,,,,,,,,,,,,,,,+
curr_bdw,,,,,,,,,,,,,,,,,,,,,,,,,,+
port_id,,,,,,,,,,,,,,,,,,,,,,,,,,+
aps_data,,,,,,,,,+,+,,,,,,,,,,,,,,,,
tlvs,,+,+,+,+,,,+,,,,,,,+,+,+,,,,,,+,+,+,
opt_data,,,,,,,,,,,,,,,,,,+,+,+,+,,,,,
end_tlv,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+,+


"""
# from scapy.config import conf
# from scapy.error import Scapy_Exception
# from scapy.layers.l2 import Ether, Dot1Q
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    ConditionalField,
    EnumField,
    FCSField,
    FlagsField,
    IntField,
    LenField,
    LongField,
    MACField,
    MultipleTypeField,
    NBytesField,
    OUIField,
    PacketField,
    PacketListField,
    ShortField,
)
from scapy.layers.l2 import Dot1Q
from scapy.packet import Packet, bind_layers
from binascii import crc32
import struct


class MepIdField(ShortField):
    """
    Short field with insignificant three leading bytes
    """

    def __init__(self, name, default):
        super().__init__(
            name, default & 0x1FFF if default is not None else default
        )


class OAM_TLV(Packet):
    """
    OAM TLV
    """

    name = "OAM TLV"
    fields_desc = [ByteField("type", 1), LenField("length", None)]


class OAM_DATA_TLV(Packet):
    """
    OAM Data TLV
    """

    name = "OAM Data TLV"
    fields_desc = [ByteField("type", 3), LenField("length", None)]


class OAM_TEST_TLV(Packet):
    """
    OAM test TLV data
    """

    name = "OAM test TLV"

    fields_desc = [
        ByteField("type", 32),
        MultipleTypeField(
            [
                (
                    LenField("length", None, adjust=lambda l: l+1),
                    lambda p: p.pat_type == 1 or p.pat_type == 3,
                )
            ],
            LenField("length", None),
        ),
        EnumField(
            "pat_type",
            0,
            {
                0: "Null signal without CRC-32",
                1: "Null signal with CRC-32",
                2: "PRBS 2^-31 - 1 without CRC-32",
                3: "PRBS 2^-31 - 1 with CRC-32",
            },
            fmt="B",
        ),
        ConditionalField(
            FCSField("crc", None, fmt="I"),
            lambda p: p.pat_type == 1 or p.pat_type == 3,
        ),
    ]

    def post_build(self, p, pay):
        if p[3] == 1 or p[3] == 3:
            p1 = p
            p2 = pay[:-4]
            p3 = struct.pack("!I", crc32(p1 + p2))
            return p1 + p2 + p3
        else:
            return p + pay


class OAM_LTM_TLV(Packet):
    """
    OAM LTM TLV data
    """

    name = "OAM LTM Egress ID TLV"

    fields_desc = [
        ByteField("type", 7),
        LenField("length", 8),
        LongField("egress_id", 0),
    ]


class OAM_LTR_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Egress ID TLV"

    fields_desc = [
        ByteField("type", 8),
        LenField("length", 16),
        LongField("last_egress_id", 0),
        LongField("next_egress_id", 0),
    ]


class OAM_LTR_IG_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Ingress TLV"

    fields_desc = [
        ByteField("type", 5),
        LenField("length", None),
        ByteField("ingress_act", 0),
        MACField("ingress_mac", None),
    ]


class OAM_LTR_EG_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Egress TLV"

    fields_desc = [
        ByteField("type", 6),
        LenField("length", None),
        ByteField("egress_act", 0),
        MACField("egress_mac", None),
    ]


class OAM_TEST_ID_TLV(Packet):
    """
    OAM Test ID TLV data
    """

    name = "OAM Test ID TLV"

    fields_desc = [
        ByteField("type", 36),
        LenField("length", None),
        IntField("test_id", 0),
    ]


def guess_tlv_type(pkt, lst, cur, remain):
    if remain[0] == 0:
        return None
    elif remain[0] == 3:
        return OAM_DATA_TLV
    elif remain[0] == 5:
        return OAM_LTR_IG_TLV
    elif remain[0] == 6:
        return OAM_LTR_EG_TLV
    elif remain[0] == 7:
        return OAM_LTM_TLV
    elif remain[0] == 8:
        return OAM_LTR_TLV
    elif remain[0] == 32:
        return OAM_TEST_TLV
    elif remain[0] == 32:
        return OAM_TEST_ID_TLV
    else:
        return OAM_TLV


class PTP_TIMESTAMP(Packet):
    """
    PTP timestamp
    """

    # TODO: should be a part of PTP layer
    name = "PTP timestamp"
    fields_desc = [IntField("seconds", 0), IntField("nanoseconds", 0)]

    def extract_padding(self, s):
        return b"", s


class APS(Packet):
    """
    Linear protective switching APS data packet
    """

    name = "APS"

    fields_desc = [
        BitEnumField(
            "req_st",
            0,
            4,
            {
                0b0000: "No request (NR)",
                0b0001: "Do not request (DNR)",
                0b0010: "Reverse request (RR)",
                0b0100: "Exercise (EXER)",
                0b0101: "Wait-to-restore (WTR)",
                0b0110: "Deprecated",
                0b0111: "Manual switch (MS)",
                0b1001: "Signal degrade (SD)",
                0b1011: "Signal fail for working (SF)",
                0b1101: "Forced switch (FS)",
                0b1110: "Signal fail on protection (SF-P)",
                0b1111: "Lockout of protection (LO)",
            },
        ),
        FlagsField(
            "prot_type",
            0,
            4,
            {
                (1 << 3): "A",
                (1 << 2): "B",
                (1 << 1): "D",
                (1 << 0): "R",
            },
        ),
        EnumField(
            "req_sig", 0, {0: "Null signal", 1: "Normal traffic"}, fmt="B"
        ),
        EnumField(
            "br_sig", 0, {0: "Null signal", 1: "Normal traffic"}, fmt="B"
        ),
        FlagsField("br_type", 0, 8, {(1 << 7): "T"}),
    ]

    def extract_padding(self, s):
        return b"", s


class RAPS(Packet):
    """
    Ring protective switching R-APS data packet
    """

    name = "R-APS"

    fields_desc = [
        BitEnumField(
            "req_st",
            0,
            4,
            {
                0b0000: "No request (NR)",
                0b0111: "Manual switch (MS)",
                0b1011: "Signal fail(SF)",
                0b1101: "Forced switch (FS)",
                0b1110: "Event",
            },
        ),
        MultipleTypeField(
            [
                (
                    BitEnumField("sub_code", 0, 4, {0b0000: "Flush"}),
                    lambda p: p.req_st == 0b1110,
                )
            ],
            BitField("sub_code", 0, 4),
        ),
        FlagsField(
            "status",
            0,
            8,
            {
                (1 << 7): "RB",
                (1 << 6): "DNF",
                (1 << 5): "BPR",
            },
        ),
        MACField("node_id", None),
        NBytesField("resv", 0, 24),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM(Packet):
    """
    OAM data unit
    """

    name = "OAM"

    OPCODES = {
        1: "Continuity Check Message (CCM)",
        3: "Loopback Message (LBM)",
        2: "Loopback Reply (LBR)",
        5: "Linktrace Message (LTM)",
        4: "Linktrace Reply (LTR)",
        32: "Generic Notification Message (GNM)",
        33: "Alarm Indication Signal (AIS)",
        35: "Lock Signal (LCK)",
        37: "Test Signal (TST)",
        39: "Automatic Protection Switching (APS)",
        40: "Ring-Automatic Protection Switching (R-APS)",
        41: "Maintenance Communication Channel (MCC)",
        43: "Loss Measurement Message (LMM)",
        42: "Loss Measurement Reply (LMR)",
        45: "One Way Delay Measurement (1DM)",
        47: "Delay Measurement Message (DMM)",
        46: "Delay Measurement Reply (DMR)",
        49: "Experimental OAM Message (EXM)",
        48: "Experimental OAM Reply (EXR)",
        51: "Vendor Specific Message (VSM)",
        50: "Vendor Specific Reply (VSR)",
        52: "Client Signal Fail (CSF)",
        53: "One Way Synthetic Loss Measurement (1SL)",
        55: "Synthetic Loss Message (SLM)",
        54: "Synthetic Loss Reply (SLR)",
    }

    TIME_FLAGS = {
        1: "Trans Int 3.33ms, max Lifetime 11.66ms, min Lifetime 10.83ms",
        2: "Trans Int 10ms, max Lifetime 35ms, min Lifetime 32.5ms",
        3: "Trans Int 100ms, max Lifetime 350ms, min Lifetime 325ms",
        4: "Trans Int 1s, max Lifetime 3.5s, min Lifetime 3.25s",
        5: "Trans Int 10s, max Lifetime 35s, min Lifetime 32.5s",
        6: "Trans Int 1min, max Lifetime 3.5min, min Lifetime 3.25min",
    }

    PERIOD_FLAGS = {
        0b100: "1 frame per second",
        0b110: "1 frame per minute",
    }

    BNM_PERIOD_FLAGS = {
        0b100: "1 frame per second",
        0b101: "1 frame per 10 seconds",
        0b110: "1 frame per minute",
    }

    fields_desc = [
        # Common fields
        BitField("mel", 0, 3),
        MultipleTypeField(
            [(BitField("version", 1, 5), lambda x: x.opcode in [43, 45, 47])],
            BitField("version", 0, 5),
        ),
        EnumField("opcode", None, OPCODES, fmt="B"),
        MultipleTypeField(
            [
                (
                    FlagsField("flags", 0, 5, {(1 << 4): "RDI"}),
                    lambda x: x.opcode == 1,
                ),
                (
                    FlagsField("flags", 0, 8, {(1 << 7): "HWonly"}),
                    lambda x: x.opcode == 5,
                ),
                (
                    FlagsField(
                        "flags",
                        0,
                        8,
                        {
                            (1 << 7): "HWonly",
                            (1 << 6): "FwdYes",
                            (1 << 5): "TerminalMEP",
                        },
                    ),
                    lambda x: x.opcode == 4,
                ),
                (BitField("flags", 0, 5), lambda x: x.opcode in [33, 35, 32]),
                (
                    FlagsField("flags", 0, 8, {(1 << 0): "Type"}),
                    lambda x: x.opcode in [43, 45, 47],
                ),
                (
                    BitEnumField(
                        "flags",
                        0,
                        5,
                        {
                            0b000: "LOS",
                            0b001: "FDI",
                            0b010: "RDI",
                            0b011: "DCI",
                        },
                    ),
                    lambda x: x.opcode == 52,
                ),
            ],
            ByteField("flags", 0),
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        BitEnumField("period", 1, 3, TIME_FLAGS),
                        lambda x: x.opcode == 1,
                    ),
                    (
                        BitEnumField("period", 0b110, 3, BNM_PERIOD_FLAGS),
                        lambda x: x.opcode == 1,
                    ),
                ],
                BitEnumField("period", 0b110, 3, PERIOD_FLAGS),
            ),
            lambda x: x.opcode in [1, 33, 35, 52, 32],
        ),
        MultipleTypeField(
            [
                (ByteField("tlv_offset", 70), lambda x: x.opcode == 1),
                (
                    ByteField("tlv_offset", 4),
                    lambda x: x.opcode in [3, 2, 37, 39],
                ),
                (ByteField("tlv_offset", 17), lambda x: x.opcode == 5),
                (ByteField("tlv_offset", 6), lambda x: x.opcode == 4),
                (ByteField("tlv_offset", 32), lambda x: x.opcode in [40, 47]),
                (ByteField("tlv_offset", 12), lambda x: x.opcode == 43),
                (
                    ByteField("tlv_offset", 16),
                    lambda x: x.opcode in [45, 54, 53],
                ),
                (ByteField("tlv_offset", 13), lambda x: x.opcode == 32),
                (
                    ByteField("tlv_offset", 10),
                    lambda x: x.opcode == 41 \
                    and x.subopcode == 1 \
                    and x.oui == 6567,
                ),
            ],
            ByteField("tlv_offset", 0),
        ),
        # End common fields
        ConditionalField(
            IntField("seq_num", 0), lambda x: x.opcode in [1, 3, 2, 37]
        ),
        ConditionalField(IntField("trans_id", 0),
                         lambda x: x.opcode in [5, 4]),
        ConditionalField(
            OUIField("oui", None), lambda x: x.opcode in [41, 49, 48, 51, 50]
        ),
        ConditionalField(
            ByteField("subopcode", 0),
            lambda x: x.opcode in [41, 49, 48, 51, 50, 32],
        ),
        ConditionalField(
            MepIdField("mep_id", 0),
            lambda x: x.opcode == 1 \
            or (x.opcode == 41 and x.subopcode == 1 and x.oui == 6567),
        ),
        ConditionalField(
            NBytesField("meg_id", 0, sz=48), lambda x: x.opcode == 0x01
        ),
        ConditionalField(
            ShortField("src_mep_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            ShortField("rcv_mep_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            IntField("test_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            IntField("txfcf", 0), lambda x: x.opcode in [1, 43, 42, 55, 54, 53]
        ),
        ConditionalField(IntField("rxfcb", 0), lambda x: x.opcode == 1),
        ConditionalField(IntField("rxfcf", 0), lambda x: x.opcode in [43, 42]),
        ConditionalField(
            IntField("txfcb", 0), lambda x: x.opcode in [1, 43, 42, 55, 54]
        ),
        ConditionalField(IntField("resv", 0), lambda x: x.opcode in [1, 53]),
        ConditionalField(ByteField("ttl", 0), lambda x: x.opcode in [5, 4]),
        ConditionalField(MACField("orig_mac", None), lambda x: x.opcode == 5),
        ConditionalField(MACField("targ_mac", None), lambda x: x.opcode == 5),
        ConditionalField(ByteField("relay_act", None),
                         lambda x: x.opcode == 4),
        ConditionalField(
            PacketField("txtsf", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [45, 47, 46],
        ),
        ConditionalField(
            PacketField("rxtsf", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [45, 47, 46],
        ),
        ConditionalField(
            PacketField("txtsb", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [47, 46],
        ),
        ConditionalField(
            PacketField("rxtsb", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [47, 46],
        ),
        ConditionalField(
            IntField("expct_dur", None),
            lambda x: x.opcode == 41 and x.subopcode == 1 and x.oui == 6567,
        ),
        ConditionalField(IntField("nom_bdw", None), lambda x: x.opcode == 32),
        ConditionalField(IntField("curr_bdw", None), lambda x: x.opcode == 32),
        ConditionalField(IntField("port_id", None), lambda x: x.opcode == 32),
        ConditionalField(
            PacketField("aps", APS(), APS), lambda x: x.opcode == 39
        ),
        ConditionalField(
            PacketField("raps", RAPS(), RAPS), lambda x: x.opcode == 40
        ),
        ConditionalField(
            PacketListField("tlvs", [], next_cls_cb=guess_tlv_type),
            lambda x: x.opcode in [3, 2, 5, 4, 37, 45, 47, 46, 55, 54, 53],
        ),
        ConditionalField(
            IntField("opt_data", None),
            lambda x: x.opcode in [49, 48, 51, 50] and False,
        ),  # FIXME: field documented elsewhere
        # TODO: add EXM, EXR, VSM data
        ByteField("end_tlv", 0),
    ]


bind_layers(Dot1Q, OAM, type=0x8902)
