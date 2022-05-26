# from scapy.contrib.oam import OAM, RAPS
# from scapy.utils import wrpcap, tcpdump, rdpcap
# from scapy.layers.l2 import Dot1Q, Ether
# from scapy.plist import PacketList

# pkt = Ether(dst="01:19:a7:00:00:0c",
#             src="00:a0:12:27:0d:a6") / \
#     Dot1Q(prio=0b111, type=0x8902, vlan=505) / \
#     OAM(opcode="Ring-Automatic Protection Switching (R-APS)",
#         mel=7,
#         version=1,
#         raps=RAPS(req_st="No request (NR)",
#                   status="RB+BPR",
#                   node_id="00:a0:12:27:0d:a6"))
# pkt.show()
# wrpcap("/tmp/1.pcapng", Ether(pkt.build()))
# tcpdump(pktlist=rdpcap("/tmp/gvrp.pcapng.gz"), prog="tshark", args=["-r", "-", "garp"])

from scapy.automaton import Automaton, ATMT
from enum import Enum


class PORT_TYPE(Enum):
    NORMAL = Enum.auto()
    NEIGHBOR = Enum.auto()
    OWNER = Enum.auto()


class REQ_PRIO(Enum):
    CLEAR = 1
    FS = 2
    RAPS_FS = 3
    LOCAL_SF = 4
    LOCAL_CLEAR_SF = 5
    RAPS_SF = 6
    RAPS_MS = 7
    MS = 8
    WTR_EXP = 9
    WTR_RUN = 10
    WTB_EXP = 11
    WTB_RUN = 12
    RAPS_NR_RB = 13
    RAPS_NR = 14
    NONE = 100


class RAPS_TYPE(Enum):
    NR = Enum.auto()
    FS = Enum.auto()
    FS_DNF = Enum.auto()
    SF = Enum.auto()
    MS = Enum.auto()
    NR = Enum.auto()
    NR_RB = Enum.auto()


class Port():
    def __init__(self, name, port_type):
        # type: (str, PORT_TYPE) -> None
        self.name = name
        self.type = port_type
        self.blocked = False
        self.failed = False

    def __str__(self):
        # type: () -> str
        return self.name

    def block(self):
        self.blocked = True

    def unblock(self):
        self.blocked = False

    def send(self, msg):
        pass

    def check_failed(self):
        pass


class ERPS(Automaton):

    def __init__(self, *args, **kwargs):
        super(ERPS, self).__init__(*args, **kwargs)

    def parse_args(self,
                   node_id,
                   vlan,
                   port1,
                   port2,
                   guard_timeout=1,
                   wtr_timeout=1,
                   revertive=False,
                   **kargs):
        super(ERPS, self).parse_args(**kargs)
        if port1 is None or port2 is None:
            raise ValueError("ports cannot be undefined")
        self.vlan = vlan  # type: int
        self.node_id = node_id  # type: str
        self.port1 = port1  # type: Port
        self.port2 = port2  # type: Port
        self.wtr_timeout = wtr_timeout  # type: float
        self.wtr_guard = guard_timeout  # type: float
        self.req = REQ_PRIO.NONE  # type: REQ_PRIO
        self.req_port = ""  # type: str
        self.guard_timer = False  # type: bool
        self.wtr_timer = False  # type: bool
        self.wtb_timer = False  # type: bool
        self.tx_raps_type = RAPS_TYPE.NR  # type: RAPS_TYPE
        self.tx_raps = False  # type: bool
        self.revertive = revertive  # type: bool
        if port1.type == PORT_TYPE.OWNER or port2.type == PORT_TYPE.OWNER:
            self.node_type = PORT_TYPE.OWNER  # type: PORT_TYPE
        elif port1.type == PORT_TYPE.NEIGHBOR or port2.type == PORT_TYPE.NEIGHBOR:
            self.node_type = PORT_TYPE.NEIGHBOR  # type: PORT_TYPE
        else:
            self.node_type = PORT_TYPE.NORMAL  # type: PORT_TYPE

    def port_by_name(self, name):
        # type: (str) -> Port
        if self.port1.name == name:
            return (self.port1, self.port2)
        elif self.port2.name == name:
            return (self.port2, self.port1)
        else:
            raise RuntimeError("no such port")

    def block_port(self, port):
        # type: (Port) -> None
        self.debug(2, f"blocking port {port}")
        port.block()

    def unblock_port(self, port):
        # type: (Port) -> None
        self.debug(2, f"unblocking port {port}")
        port.unblock()

    def send_raps(self, msg_type):
        # type: (RAPS_TYPE) -> None
        self.debug(2, f"sending RAPS {msg_type}")
        if self.tx_raps_type != msg_type:
            self.tx_raps_type = msg_type
            [[port.send(msg_type) for port in [self.port1, self.port2]] for _ in range(3)]
        self.tx_raps = True

    def stop_raps(self):
        self.tx_raps = False

    def flush_fdb(self):
        pass

    # State machine

    @ATMT.state(initial=1)
    def INITIAL(self):
        self.req = REQ_PRIO.NONE
        self.req_port = self.port1
        self.guard_timer = False
        self.wtr_timer = False
        self.wtb_timer = False
        # block RPL, unblock other
        block, unblock = (self.port1, self.port2) \
            if self.node_type != PORT_TYPE.NORMAL and \
               self.port1.type != PORT_TYPE.NORMAL \
                   else (self.port2, self.port1)
        block.block()
        unblock.unblock()
        self.send_raps([self.port1, self.port2], RAPS_TYPE.NR)
        if self.node_type == PORT_TYPE.OWNER and self.revertive:
            self.wtr_timer = True
        raise self.PENDING()

    @ATMT.state()
    def IDLE(self):
        pass

    @ATMT.condition(IDLE, prio=REQ_PRIO.FS.value)
    def idle_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            block, unblock = self.port_by_name(self.req_port)
            block.block()
            unblock.unblock()
            if self.req_port.blocked():
                self.send_raps(RAPS_TYPE.FS_DNF)
            else:
                self.send_raps(RAPS_TYPE.FS)
                self.flush_fdb()
            raise self.FORCED_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_FS.value)
    def idle_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            self.port1.unblock()
            self.port2.unblock()
            self.stop_raps()
            raise self.FORCED_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.LOCAL_SF.value)
    def idle_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            raise self.PROTECTION()

    @ATMT.condition(IDLE, prio=REQ_PRIO.LOCAL_CLEAR_SF.value)
    def idle_ev_local_clear_sf(self):
        if self.req == REQ_PRIO.LOCAL_CLEAR_SF:
            raise self.IDLE()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_SF.value)
    def idle_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            raise self.PROTECTION()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_MS.value)
    def idle_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            raise self.MANUAL_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.MS.value)
    def idle_ev_ms(self):
        if self.req == REQ_PRIO.MS:
            raise self.MANUAL_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_NR_RB.value)
    def idle_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            raise self.IDLE()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_NR.value)
    def idle_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            raise self.IDLE()

    @ATMT.state()
    def PROTECTION(self):
        pass

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.FS.value)
    def protection_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_FS.value)
    def protection_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.LOCAL_SF.value)
    def protection_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            raise self.PROTECTION()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.LOCAL_CLEAR_SF.value)
    def protection_ev_local_clear_sf(self):
        if self.req == REQ_PRIO.LOCAL_CLEAR_SF:
            raise self.PENDING()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.WTR_EXP.value)
    def protection_ev_wtr_exp(self):
        if self.req == REQ_PRIO.WTR_EXP:
            raise self.IDLE()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.WTB_EXP.value)
    def protection_ev_wtb_exp(self):
        if self.req == REQ_PRIO.WTB_EXP:
            raise self.IDLE()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_NR_RB.value)
    def protection_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            raise self.PENDING()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_NR.value)
    def protection_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            raise self.PENDING()

    @ATMT.state()
    def MANUAL_SWITCH(self):
        pass

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.CLEAR.value)
    def manual_switch_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            raise self.PENDING()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.FS.value)
    def manual_switch_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_FS.value)
    def manual_switch_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.LOCAL_SF.value)
    def manual_switch_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            raise self.PROTECTION()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_SF.value)
    def manual_switch_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            raise self.PROTECTION()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_MS.value)
    def manual_switch_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            raise self.PENDING() or self.IDLE()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_NR_RB.value)
    def manual_switch_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            raise self.PENDING()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_NR.value)
    def manual_switch_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            raise self.PENDING()

    @ATMT.state()
    def FORCED_SWITCH(self):
        pass

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.CLEAR.value)
    def forced_switch_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            raise self.IDLE()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.FS.value)
    def forced_switch_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.RAPS_NR_RB.value)
    def forced_switch_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            raise self.PENDING()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.RAPS_NR.value)
    def forced_switch_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            raise self.PENDING()

    @ATMT.state()
    def PENDING(self):
        pass

    @ATMT.condition(PENDING, prio=REQ_PRIO.CLEAR.value)
    def pending_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.FS.value)
    def pending_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_FS.value)
    def pending_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            raise self.FORCED_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.LOCAL_SF.value)
    def pending_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            raise self.PROTECTION()

    @ATMT.condition(PENDING, prio=REQ_PRIO.LOCAL_CLEAR_SF.value)
    def pending_ev_local_clear_sf(self):
        if self.req == REQ_PRIO.LOCAL_CLEAR_SF:
            raise self.PENDING()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_SF.value)
    def pending_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            raise self.PROTECTION()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_MS.value)
    def pending_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            raise self.MANUAL_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.MS.value)
    def pending_ev_ms(self):
        if self.req == REQ_PRIO.MS:
            raise self.MANUAL_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.WTR_EXP.value)
    def pending_ev_wtr_exp(self):
        if self.req == REQ_PRIO.WTR_EXP:
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.WTB_EXP.value)
    def pending_ev_wtb_exp(self):
        if self.req == REQ_PRIO.WTB_EXP:
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_NR_RB.value)
    def pending_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_NR.value)
    def pending_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            raise self.PENDING()


ERPS.graph()
# sm = ERPS(port1=1, port2=2, port1_type=PORT_TYPE.OWNER, debug=5)
# sm.run()
