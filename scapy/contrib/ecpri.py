# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Evolved Common Public Radio Interface (eCPRI)
# scapy.contrib.status = loads


"""
    Evolved Common Public Radio Interface (eCPRI)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Abbath
    :modified:  Sergey Matsievskiy, matsievskiysv@gmail.com

    :description:

        This module provides Scapy layers for the eCPRI protocol.

        normative references:
          - eCPRI specification v2 (2019-05-10)
"""

from scapy.all import (
    FlagsField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    NBytesField,
    EnumField,
    Ether,
    IntField,
    LenField,
    ConditionalField,
    LongField,
    Packet,
    PacketListField,
    Raw,
    ShortField,
    StrLenField,
    PacketField,
    UDP,
    XByteField,
    XIntField,
    XShortField,
    bind_layers,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ECPRI_ETHERTYPE = 0xAEFE
ECPRI_UDP_PORT = 6000

# eCPRI spec V2.0 Table 4
ECPRI_MSG_TYPES = {
    0: "IQ Data",
    1: "Bit Sequence",
    2: "Real-Time Control Data",
    3: "Generic Data Transfer",
    4: "Remote Memory Access",
    5: "One-Way Delay Measurement",
    6: "Remote Reset",
    7: "Event Indication",
}

# eCPRI spec V2.0 Table 5
ECPRI_RMA_RW = {
    0: "Read",
    1: "Write",
    2: "Write No Resp",
}

# eCPRI spec V2.0 Table 6
ECPRI_RMA_REQ_RESP = {
    0: "Request",
    1: "Response",
    2: "Failure",
}

# eCPRI spec V2.0 Table 8
ECPRI_OWD_ACTION = {
    0: "Request",
    1: "Request Follow Up",
    2: "Response",
    3: "Remote Request",
    4: "Remote request Follow Up",
    5: "Follow Up",
}

# eCPRI spec V2.0 Table 9
ECPRI_RESET_CODE = {
    0x00: "Reserved",
    0x01: "Remote reset request",
    0x02: "Remote reset response",
}

# eCPRI spec V2.0 Table 10
ECPRI_EVENT_TYPE = {
    0x00: "Fault(s) Indication",
    0x01: "Fault(s) Indication Acknowledge",
    0x02: "Notification(s) Indication",
    0x03: "Synchronization Request",
    0x04: "Synchronization Acknowledge",
    0x05: "Synchronization End Indication",
}

# eCPRI spec V2.0 Table 12
ECPRI_RAISE_CEASE = {
    0x0: "Raise a fault",
    0x1: "Cease a fault",
}

# eCPRI spec V2.0 Table 13
ECPRI_FAULT_NOTIF = {
    0x000: "General Userplane HW Fault",
    0x001: "General Userplane SW Fault",
    0x002: "Unknown",
    0x003: "CPRI Port(s) – Loss of Frame",
    0x004: "CPRI Port(s) – Loss of Sync",
    0x005: "Ethernet Port(s) – Link Down",
    0x006: "Ethernet Port(s) – Frame Loss",
    0x007: "Ethernet Port(s) – Loss of Sync",
    0x008: "Timing – Loss of PTP/SyncE Lock",
    0x009: "Transport – Buffer Overflow",
    0x00A: "Transport – Buffer Underflow",
    # 0x00B – 0x3FF: reserved / vendor-specific
}


class eCPRI_TS(Packet):
    """eCPRI timestamp."""

    name = "eCPRI timestamp"
    fields_desc = [
        IntField("seconds", 0),
        IntField("nanoseconds", 0)
    ]

    def extract_padding(self, s):
        return b"", s


class eCPRI_TS6(Packet):
    """eCPRI timestamp with 6 byte second field."""

    name = "eCPRI timestamp"
    fields_desc = [
        NBytesField("seconds", 0, 6),
        IntField("nanoseconds", 0)
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# eCPRI Common Header (4 bytes)
# ---------------------------------------------------------------------------


class eCPRI(Packet):
    """
    eCPRI common header.

    eCPRI spec V2.0 Sec 3.2.3.2
    """

    name = "eCPRI"

    fields_desc = [
        BitField("revision", 1, 4),
        BitField("reserved", 0, 3),
        BitField("C", 0, 1),
        ByteEnumField("msg_type", 0, ECPRI_MSG_TYPES),
        LenField("payload_size", None, fmt="!H"),
    ]

    def guess_payload_class(self, payload):
        cls_map = {
            0: eCPRI_IQ_Data,
            1: eCPRI_Bit_Sequence,
            2: eCPRI_RT_Control_Data,
            3: eCPRI_Generic_Data_Transfer,
            4: eCPRI_Remote_Memory_Access,
            5: eCPRI_One_Way_Delay,
            6: eCPRI_Remote_Reset,
            7: eCPRI_Event_Indication,
            8: eCPRI_IWF_StartUp,
        }
        return cls_map.get(self.msg_type, Raw)


# ---------------------------------------------------------------------------
# Message Type 0 – IQ Data
# ---------------------------------------------------------------------------


class eCPRI_IQ_Data(Packet):
    """
    eCPRI IQ Data.

    eCPRI spec V2.0 Sec 3.2.4.1
    """

    name = "eCPRI IQ Data"
    fields_desc = [
        XShortField("pc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "iq_data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 1 – Bit Sequence
# ---------------------------------------------------------------------------


class eCPRI_Bit_Sequence(Packet):
    """
    eCPRI IQ Data.

    eCPRI spec V2.0 Sec 3.2.4.2
    """

    name = "eCPRI Bit Sequence"
    fields_desc = [
        XShortField("pc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "bit_seq",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 2 – Real-Time Control Data
# ---------------------------------------------------------------------------


class eCPRI_RT_Control_Data(Packet):
    """
    eCPRI Real-Time Control Data.

    eCPRI spec V2.0 Sec 3.2.4.3
    """

    name = "eCPRI RT Control Data"
    fields_desc = [
        XShortField("rtc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "rtc_data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 3 – Generic Data Transfer
# ---------------------------------------------------------------------------


class eCPRI_Generic_Data_Transfer(Packet):
    """
    eCPRI Generic Data Transfer.

    eCPRI spec V2.0 Sec 3.2.4.4
    """

    name = "eCPRI Generic Data Transfer"
    fields_desc = [
        XIntField("pc_id", 0),
        IntField("seq_id", 0),
        StrLenField(
            "data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 8, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 4 – Remote Memory Access
# ---------------------------------------------------------------------------


class eCPRI_Remote_Memory_Access(Packet):
    """
    eCPRI Remote Memory Access.

    eCPRI spec V2.0 Sec 3.2.4.5
    """

    name = "eCPRI Remote Memory Access"
    fields_desc = [
        XByteField("rma_id", 0),
        BitEnumField("read_write", 0, 4, ECPRI_RMA_RW),
        BitEnumField("req_resp", 0, 4, ECPRI_RMA_REQ_RESP),
        ShortField("element_id", 0),
        BitField("address", 0, 48),
        ShortField("length", 0),
        StrLenField(
            "data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 12, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 5 – One-Way Delay Measurement
# ---------------------------------------------------------------------------


class eCPRI_One_Way_Delay(Packet):
    """
    eCPRI One-Way Delay Measurement.

    eCPRI spec V2.0 Sec 3.2.4.6
    """

    name = "eCPRI One-Way Delay Measurement"
    fields_desc = [
        XByteField("measurement_id", 0),
        ByteEnumField("action_type", 0, ECPRI_OWD_ACTION),
        PacketField("ts", eCPRI_TS6(), eCPRI_TS6),
        PacketField("comp_val", eCPRI_TS(), eCPRI_TS),
        StrLenField(
            "dummy",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 20, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 6 – Remote Reset
# ---------------------------------------------------------------------------


class eCPRI_Remote_Reset(Packet):
    """
    eCPRI Remote Reset.

    eCPRI spec V2.0 Sec 3.2.4.7
    """

    name = "eCPRI Remote Reset"
    fields_desc = [
        XShortField("reset_id", 0),
        ByteEnumField("reset_code", 0, ECPRI_RESET_CODE),
        StrLenField(
            "vendor_specific",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 3, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 7 – Event Indication — Element sub-packet
# ---------------------------------------------------------------------------

ECPRI_ELEMENT_SIZE = 8  # bytes per fault/notification element


class eCPRI_Fault_Notification(Packet):
    """
    eCPRI Single Fault / Notification element inside an Event Indication.

    eCPRI spec V2.0 Sec 3.2.4.8
    """

    name = "eCPRI Fault/Notification Element"

    fields_desc = [
        XShortField("element_id", 0),
        BitEnumField("raise_cease", 0, 4, ECPRI_RAISE_CEASE),
        BitEnumField("fault_notif", 0, 12, ECPRI_FAULT_NOTIF),
        XIntField("additional_info", 0),
    ]

    def extract_padding(self, s):
        """Each element is exactly 8 bytes; remaining bytes are padding."""
        return b"", s


class eCPRI_Event_Indication(Packet):
    """
    eCPRI Event Indication message.

    eCPRI spec V2.0 Sec 3.2.4.8
    """

    name = "eCPRI Event Indication"

    fields_desc = [
        XByteField("event_id", 0),
        ByteEnumField("event_type", 0, ECPRI_EVENT_TYPE),
        ByteField("sequence_number", 0),
        ByteField("number_faults_notif", 0),
        PacketListField(
            "elements",
            [],
            eCPRI_Fault_Notification,
            count_from=lambda pkt: pkt.number_faults_notif,
        ),
    ]

    def post_build(self, pkt, pay):
        """Auto-fill number_faults_notif if left at 0 but elements exist."""
        if self.number_faults_notif == 0 and self.elements:
            count = len(self.elements)
            pkt = pkt[:3] + bytes([count]) + pkt[4:]
        return pkt + pay

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 8 – IWF Start-Up
# ---------------------------------------------------------------------------


class eCPRI_IWF_StartUp(Packet):
    """
    eCPRI IWF Start-Up.

    eCPRI spec V2.0 Sec 3.2.4.9
    """

    name = "eCPRI IWF Start-Up"
    fields_desc = [
        XShortField("pc_id", 0),
        ByteField("hyperframe", 0),
        ByteField("basic_frame", 0),
        IntField("ts", 0),
        FlagsField(
            "conf",
            0,
            3,
            {
                (1 << 2): "FEC",
                (1 << 1): "scrambling",
            },
        ),
        BitField("line_rate", 0, 5),
        StrLenField(
            "data_transferred",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 9, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 9 – IWF Operation
# ---------------------------------------------------------------------------

class _eCPRI_IWF_Chunk(Packet):
    """
    eCPRI chunk element inside an IWF operation message.

    eCPRI spec V2.0 Sec 3.2.4.9
    """

    name = "eCPRI IWF Chunk"

    fields_desc = [
        FlagsField(
            "conf",
            0,
            6,
            {
                (1 << 5): "Control Word",
                (1 << 4): "Control Word Extension",
                (1 << 3): "Data Block",
                (1 << 2): "Error",
                (1 << 1): "Bitmask",
            },
        ),
        BitField("bff", 0, 2),
        ConditionalField(
            IntField("n", 0),
            lambda pkt: "Bitmask" in pkt.conf,
        ),
        ConditionalField(
            StrLenField(
                "bitmask",
                b"",
                length_from=lambda pkt: pkt.n,
            ),
            lambda pkt: "Bitmask" in pkt.conf,
        ),
        # FIXME: unclear how to get size of "data_transferred" field.
        StrLenField(
            "data_transferred",
            b"",
            length_from=lambda pkt: 0,
        ),
    ]

    def extract_padding(self, s):
        """Each element is exactly 8 bytes; remaining bytes are padding."""
        return b"", s


# ---------------------------------------------------------------------------
# Layer bindings
# ---------------------------------------------------------------------------

bind_layers(Ether, eCPRI, type=ECPRI_ETHERTYPE)
bind_layers(UDP, eCPRI, dport=ECPRI_UDP_PORT)
bind_layers(UDP, eCPRI, sport=ECPRI_UDP_PORT)
