# from scapy.contrib.oam import OAM, RAPS
# from scapy.utils import wrpcap, tcpdump, rdpcap
# from scapy.layers.l2 import Dot1Q, Ether
# from scapy.plist import PacketList

# load_contrib("oam")
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
from scapy.packet import Packet
from scapy.layers.l2 import Ether, Dot1Q
from scapy.contrib.oam import RAPS, OAM
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sendp
from enum import Enum, auto, Flag
from scapy.config import conf


class PORT_TYPE(Enum):
    NORMAL = auto()
    NEIGHBOR = auto()
    OWNER = auto()


class REQ_PRIO(Enum):
    CLEAR = auto()
    FS = auto()
    RAPS_FS = auto()
    LOCAL_SF = auto()
    LOCAL_CLEAR_SF = auto()
    RAPS_SF = auto()
    RAPS_MS = auto()
    MS = auto()
    WTR_EXP = auto()
    WTR_RUN = auto()
    WTB_EXP = auto()
    WTB_RUN = auto()
    RAPS_NR_RB = auto()
    RAPS_NR = auto()
    NONE = auto()


class RAPS_FLAG(Flag):
    DNF = auto()
    RB = auto()
    FS = 0b1101
    MS = 0b0111
    NR = 0b0000
    SF = 0b1011


def generate_raps(src, node_id, ring_id, vlan, msg, rpl_blocked):
    # type: (str, str, int, int, RAPS_FLAG, bool) -> Packet
    if RAPS_FLAG.FS in msg:
        req_st = "Forced switch (FS)"
    elif RAPS_FLAG.MS in msg:
        req_st = "Manual switch (MS)"
    elif RAPS_FLAG.SF in msg:
        req_st = "Signal fail(SF)"
    elif RAPS_FLAG.NR in msg:
        req_st = "No request (NR)"
    else:
        raise ValueError("No request")

    status = []
    if RAPS_FLAG.DNF in msg:
        status.append("DNF")
    if rpl_blocked:
        status.append("RB")
    status = "+".join(status)

    return (Ether(src=src, dst=f"01:19:a7:00:00:{ring_id:02x}") /
            Dot1Q(vlan=vlan) /
            OAM(opcode=40, version=1, raps=RAPS(req_st=req_st,
                                                status=status,
                                                node_id=node_id)))


def parse_raps(pkt):
    # type: (Packet) -> tuple[str, RAPS_FLAG]
    flags = RAPS_FLAG(pkt[RAPS].req_st)
    if pkt[RAPS].req_st == (1 << 7):
        flags += RAPS_FLAG.RB
    if pkt[RAPS].req_st == (1 << 6):
        flags += RAPS_FLAG.DNF
    return (pkt[RAPS].node_id, flags)


class Port():
    def __init__(self, name, port_type):
        # type: (str, PORT_TYPE) -> None
        self.name = name
        self.type = port_type
        self.vlan = 1  # type: int
        self.ring_id = 1  # type: int
        self.blocked = False
        self.rpl_blocked = False
        self.failed = False
        self.hwaddr = get_if_hwaddr(name)
        self.node_id = self.hwaddr

    def __str__(self):
        # type: () -> str
        return self.name

    def block(self):
        # type: () -> None
        self.blocked = True
        print(f"port {self.name} block")

    def unblock(self):
        # type: () -> None
        self.blocked = False
        print(f"port {self.name} unblock")

    def send(self, msg):
        # type: (RAPS_FLAG) -> None
        if not self.blocked:
            sendp(generate_raps(self.hwaddr,
                                self.node_id,
                                self.ring_id,
                                self.vlan,
                                msg,
                                self.rpl_blocked),
                  iface=self.name)

    def check_failing(self):
        print("check failed")


class ERPS(Automaton):

    def __init__(self, *args, **kwargs):
        super(ERPS, self).__init__(*args, **kwargs)

    def master_filter(self, pkt):
        return RAPS in pkt and \
            pkt[Ether].dst[:-3] == r'01:19:a7:00:00' and \
            pkt[Ether].dst[-2:] == f"{self.ring_id:02x}"

    def parse_args(self,
                   port1,
                   port2,
                   vlan=1,
                   ring_id=1,
                   guard_timeout=1,
                   wtr_timeout=1,
                   wtb_timeout=1,
                   revertive=False,
                   **kargs):
        super(ERPS, self).parse_args(**kargs)
        if port1 is None or port2 is None:
            raise ValueError("ports cannot be undefined")
        self.vlan = vlan  # type: int
        self.node_id = get_if_hwaddr(conf.iface)  # type: str
        self.ring_id = ring_id  # type: int
        self.port1 = port1  # type: Port
        self.port2 = port2  # type: Port
        for port in [self.port1, self.port2]:
            port.vlan = self.vlan
            port.ring_id = self.ring_id
            port.node_id = self.node_id
        self.wtr_timeout = wtr_timeout  # type: float
        self.wtr_guard = guard_timeout  # type: float
        self.req = REQ_PRIO.NONE  # type: REQ_PRIO
        self.req_port = port1  # type: Port
        self.req_id = ""  # type: str
        self.guard_timer = False  # type: bool
        self.wtr_timer = False  # type: bool
        self.wtb_timer = False  # type: bool
        self.tx_raps_type = RAPS_FLAG.FS  # type: RAPS_FLAG
        self.tx_raps = False  # type: bool
        self.revertive = revertive  # type: bool
        # if guard_timeout < 1 or guard_timeout < 200:
        #     raise ValueError("The value is an integer that ranges from 1 to 200, in centiseconds")
        if port1.type == PORT_TYPE.OWNER or port2.type == PORT_TYPE.OWNER:
            self.node_type = PORT_TYPE.OWNER  # type: PORT_TYPE
        elif port1.type == PORT_TYPE.NEIGHBOR or port2.type == PORT_TYPE.NEIGHBOR:
            self.node_type = PORT_TYPE.NEIGHBOR  # type: PORT_TYPE
        else:
            self.node_type = PORT_TYPE.NORMAL  # type: PORT_TYPE

    def start_guard(self):
        self.guard_timer = True

    def stop_guard(self):
        self.guard_timer = False

    def start_wtr(self):
        self.wtr_timer = True

    def stop_wtr(self):
        self.wtr_timer = False

    def start_wtb(self):
        self.wtb_timer = True

    def stop_wtb(self):
        self.wtb_timer = False

    def port_by_name(self, name):
        # type: (str) -> (Port, Port)
        if self.port1.name == name:
            return (self.port1, self.port2)
        elif self.port2.name == name:
            return (self.port2, self.port1)
        else:
            raise RuntimeError("no such port")

    def port_by_prio(self):
        # type: () -> (Port, Port)
        if self.port1.type == PORT_TYPE.OWNER or \
           self.port1.type == PORT_TYPE.NEIGHBOR:
            return (self.port1, self.port2)
        else:
            return (self.port2, self.port1)

    def block_port(self, port):
        # type: (Port) -> None
        self.debug(2, f"blocking port {port}")
        if self.node_type == PORT_TYPE.OWNER:
            for port in [self.port1, self.port2]:
                port.rpl_blocked = True
        port.block()

    def unblock_port(self, port):
        # type: (Port) -> None
        self.debug(2, f"unblocking port {port}")
        if self.node_type == PORT_TYPE.OWNER:
            for port in [self.port1, self.port2]:
                port.rpl_blocked = False
        port.unblock()

    def send_raps(self, msg_type):
        # type: (RAPS_FLAG) -> None
        self.debug(2, f"sending RAPS {msg_type}")
        if self.tx_raps_type != msg_type:
            self.tx_raps_type = msg_type
            for port in [self.port1, self.port2]:
                for _ in range(3):
                    port.send(msg_type)
        self.tx_raps = True

    def resend_raps(self):
        # type: (RAPS_FLAG) -> None
        self.debug(2, f"resending RAPS {self.tx_raps_type}")
        if self.tx_raps:
            for port in [self.port1, self.port2]:
                port.send(self.tx_raps_type)

    def stop_raps(self):
        self.tx_raps = False

    def flush_fdb(self):
        pass

    def req_reset(self):
        self.req = REQ_PRIO.NONE

    # State machine

    @ATMT.state(initial=1)
    def INITIAL(self):
        self.req_port = self.port1
        self.stop_guard()
        self.stop_wtr()
        self.stop_wtb()
        block, unblock = self.port_by_prio()
        block.block()
        unblock.unblock()
        self.send_raps(RAPS_FLAG.NR)
        if self.node_type == PORT_TYPE.OWNER and self.revertive:
            self.start_wtr()
        self.req_reset()
        raise self.PENDING()

    @ATMT.state()
    def IDLE(self):
        pass

    @ATMT.timer(IDLE, 5)
    def idle_raps_resend(self):
        self.resend_raps()

    @ATMT.receive_condition(IDLE)
    def idle_raps_receive(self, pkt):
        self.req_port, _ = self.port_by_name(pkt.sniffed_on)
        self.req_node, self.req = parse_raps(pkt)
        raise self.IDLE()

    @ATMT.condition(IDLE, prio=REQ_PRIO.FS.value)
    def idle_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            block, unblock = self.port_by_name(self.req_port.name)
            block.block()
            unblock.unblock()
            if self.req_port.blocked:
                self.send_raps(RAPS_FLAG.FS | RAPS_FLAG.DNF)
            else:
                self.send_raps(RAPS_FLAG.FS)
                self.flush_fdb()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_FS.value)
    def idle_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            self.port1.unblock()
            self.port2.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.LOCAL_SF.value)
    def idle_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.SF | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.SF)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_SF.value)
    def idle_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_MS.value)
    def idle_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.MANUAL_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.MS.value)
    def idle_ev_ms(self):
        if self.req == REQ_PRIO.MS:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.MS | RAPS_FLAG.DNF)
            else:
                self.send_raps(RAPS_FLAG.MS)
                self.flush_fdb()
                block.block()
            unblock.unblock()
            self.req_reset()
            raise self.MANUAL_SWITCH()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_NR_RB.value)
    def idle_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            if self.node_type != PORT_TYPE.OWNER:
                self.stop_raps()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(IDLE, prio=REQ_PRIO.RAPS_NR.value)
    def idle_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            # FIXME: WTF?
            if self.node_type == PORT_TYPE.NORMAL and self.req_id > self.node_id:
                _, unblock = self.port_by_name(self.req_port.name)
                unblock.unblock()
                self.stop_raps()
            self.req_reset()
            raise self.IDLE()

    @ATMT.state()
    def PROTECTION(self):
        pass

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.FS.value)
    def protection_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.FS | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.FS)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_FS.value)
    def protection_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            self.port1.unblock()
            self.port2.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.LOCAL_SF.value)
    def protection_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.SF | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.SF)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.LOCAL_CLEAR_SF.value)
    def protection_ev_local_clear_sf(self):
        if self.req == REQ_PRIO.LOCAL_CLEAR_SF:
            self.start_guard()
            self.send_raps(RAPS_FLAG.NR)
            if self.node_type == PORT_TYPE.OWNER and self.revertive:
                self.start_wtr()
            self.req_reset()
            raise self.PENDING()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_NR_RB.value)
    def protection_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            self.req_reset()
            raise self.PENDING()

    @ATMT.condition(PROTECTION, prio=REQ_PRIO.RAPS_NR.value)
    def protection_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            if self.node_type == PORT_TYPE.OWNER and self.revertive:
                self.start_wtr()
            self.req_reset()
            raise self.PENDING()

    @ATMT.state()
    def MANUAL_SWITCH(self):
        pass

    @ATMT.timer(MANUAL_SWITCH, 5)
    def manual_switch_raps_resend(self):
        self.resend_raps()

    @ATMT.receive_condition(MANUAL_SWITCH)
    def manual_switch_raps_receive(self, pkt):
        self.req_port, _ = self.port_by_name(pkt.sniffed_on)
        self.req_node, self.req = parse_raps(pkt)
        raise self.IDLE()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.CLEAR.value)
    def manual_switch_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            if self.port1.blocked or self.port2.blocked:
                self.start_guard()
                self.send_raps(RAPS_FLAG.NR)
                if self.node_type == PORT_TYPE.OWNER and self.revertive:
                    self.start_wtb()
            self.req_reset()
            raise self.PENDING()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.FS.value)
    def manual_switch_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.FS | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.FS)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_FS.value)
    def manual_switch_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            self.port1.unblock()
            self.port2.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.LOCAL_SF.value)
    def manual_switch_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.SF | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.SF)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_SF.value)
    def manual_switch_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            self.stop_raps()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_MS.value)
    def manual_switch_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            if self.port1.blocked or self.port2.blocked:
                self.start_guard()
                self.send_raps(RAPS_FLAG.NR)
                if self.node_type == PORT_TYPE.OWNER and self.revertive:
                    self.start_wtb()
            self.req_reset()
            raise self.PENDING() or self.IDLE()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_NR_RB.value)
    def manual_switch_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            self.req_reset()
            raise self.PENDING()

    @ATMT.condition(MANUAL_SWITCH, prio=REQ_PRIO.RAPS_NR.value)
    def manual_switch_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            if self.node_type == PORT_TYPE.OWNER and self.revertive:
                self.start_wtb()
            self.req_reset()
            raise self.PENDING()

    @ATMT.state()
    def FORCED_SWITCH(self):
        pass

    @ATMT.timer(FORCED_SWITCH, 5)
    def forced_raps_resend(self):
        self.resend_raps()

    @ATMT.receive_condition(FORCED_SWITCH)
    def forced_raps_receive(self, pkt):
        self.req_port, _ = self.port_by_name(pkt.sniffed_on)
        self.req_node, self.req = parse_raps(pkt)
        raise self.IDLE()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.CLEAR.value)
    def forced_switch_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            if self.port1.blocked or self.port2.blocked:
                self.start_guard()
                self.send_raps(RAPS_FLAG.NR)
                if self.node_type == PORT_TYPE.OWNER and self.revertive:
                    self.start_wtb()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.FS.value)
    def forced_switch_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            self.req_port.block()
            self.send_raps(RAPS_FLAG.FS)
            self.flush_fdb()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.RAPS_NR_RB.value)
    def forced_switch_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            self.req_reset()
            raise self.PENDING()

    @ATMT.condition(FORCED_SWITCH, prio=REQ_PRIO.RAPS_NR.value)
    def forced_switch_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            if self.node_type == PORT_TYPE.OWNER and self.revertive:
                self.start_wtb()
            self.req_reset()
            raise self.PENDING()

    @ATMT.state()
    def PENDING(self):
        pass

    @ATMT.timer(PENDING, 5)
    def pending_raps_resend(self):
        self.resend_raps()

    @ATMT.receive_condition(PENDING)
    def pending_raps_receive(self, pkt):
        self.req_port, _ = self.port_by_name(pkt.sniffed_on)
        self.req_node, self.req = parse_raps(pkt)
        raise self.IDLE()

    @ATMT.timeout(PENDING, 1)
    def pending_wtr_timeout(self):
        if self.wtr_timer:
            self.req = REQ_PRIO.WTR_EXP
            raise self.PENDING()

    @ATMT.timeout(PENDING, 1)
    def pending_wtb_timeout(self):
        if self.wtb_timer:
            self.req = REQ_PRIO.WTB_EXP
            raise self.PENDING()

    @ATMT.condition(PENDING, prio=REQ_PRIO.CLEAR.value)
    def pending_ev_clear(self):
        if self.req == REQ_PRIO.CLEAR:
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
                block, unblock = self.port_by_prio()
                if block.blocked:
                    self.send_raps(RAPS_FLAG.NR | RAPS_FLAG.RB | RAPS_FLAG.DNF)
                else:
                    block.block()
                    self.send_raps(RAPS_FLAG.NR | RAPS_FLAG.RB)
                    self.flush_fdb()
                unblock.unblock()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.FS.value)
    def pending_ev_fs(self):
        if self.req == REQ_PRIO.FS:
            self.req_reset()
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.FS | RAPS_FLAG.DNF)
            else:
                self.send_raps(RAPS_FLAG.FS)
                self.flush_fdb()
            unblock.unblock()
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            raise self.FORCED_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_FS.value)
    def pending_ev_raps_fs(self):
        if self.req == REQ_PRIO.RAPS_FS:
            self.port1.unblock()
            self.port2.unblock()
            self.stop_raps()
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            self.req_reset()
            raise self.FORCED_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.LOCAL_SF.value)
    def pending_ev_local_sf(self):
        if self.req == REQ_PRIO.LOCAL_SF:
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.FS | RAPS_FLAG.DNF)
            else:
                self.send_raps(RAPS_FLAG.FS)
                self.flush_fdb()
            unblock.unblock()
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_SF.value)
    def pending_ev_raps_sf(self):
        if self.req == REQ_PRIO.RAPS_SF:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            self.stop_raps()
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            self.req_reset()
            raise self.PROTECTION()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_MS.value)
    def pending_ev_raps_ms(self):
        if self.req == REQ_PRIO.RAPS_MS:
            _, unblock = self.port_by_name(self.req_port.name)
            unblock.unblock()
            self.stop_raps()
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            self.req_reset()
            raise self.MANUAL_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.MS.value)
    def pending_ev_ms(self):
        if self.req == REQ_PRIO.MS:
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtr()
                self.stop_wtb()
            block, unblock = self.port_by_name(self.req_port.name)
            if block.blocked:
                self.send_raps(RAPS_FLAG.MS | RAPS_FLAG.DNF)
            else:
                block.block()
                self.send_raps(RAPS_FLAG.MS)
                self.flush_fdb()
            unblock.unblock()
            self.req_reset()
            raise self.MANUAL_SWITCH()

    @ATMT.condition(PENDING, prio=REQ_PRIO.WTR_EXP.value)
    def pending_ev_wtr_exp(self):
        if self.req == REQ_PRIO.WTR_EXP:
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtb()
                block, unblock = self.port_by_prio()
                if block.blocked:
                    self.send_raps(RAPS_FLAG.MS | RAPS_FLAG.DNF)
                else:
                    block.block()
                    self.send_raps(RAPS_FLAG.MS)
                    self.flush_fdb()
                unblock.unblock()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.WTB_EXP.value)
    def pending_ev_wtb_exp(self):
        if self.req == REQ_PRIO.WTB_EXP:
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtb()
                block, unblock = self.port_by_prio()
                if block.blocked:
                    self.send_raps(RAPS_FLAG.MS | RAPS_FLAG.DNF)
                else:
                    block.block()
                    self.send_raps(RAPS_FLAG.MS)
                    self.flush_fdb()
                unblock.unblock()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_NR_RB.value)
    def pending_ev_raps_nr_rb(self):
        if self.req == REQ_PRIO.RAPS_NR_RB:
            if self.node_type == PORT_TYPE.OWNER:
                self.stop_wtb()
                self.stop_wtr()
            elif self.node_type == PORT_TYPE.NEIGHBOR:
                block, unblock = self.port_by_prio()
                block.block()
                unblock.unblock()
                self.stop_raps()
            else:
                self.port1.unblock()
                self.port2.unblock()
                self.stop_raps()
            self.req_reset()
            raise self.IDLE()

    @ATMT.condition(PENDING, prio=REQ_PRIO.RAPS_NR.value)
    def pending_ev_raps_nr(self):
        if self.req == REQ_PRIO.RAPS_NR:
            # FIXME: WTF?
            if self.req_id > self.node_id:
                _, unblock = self.port_by_name(self.req_port.name)
                unblock.unblock()
                self.stop_raps()
            self.req_reset()
            raise self.PENDING()


conf.iface

port1 = Port("enp2s0", PORT_TYPE.OWNER)
port2 = Port("enp2s0", PORT_TYPE.NORMAL)
# port1 = Port("eth0", PORT_TYPE.NORMAL)
# port2 = Port("eth1", PORT_TYPE.NORMAL)
sm = ERPS(vlan=1, port1=port1, port2=port2, debug=3)
# sm.run()
