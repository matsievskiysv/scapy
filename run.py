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
    NORMAL = 1
    NEIGHBOR = 2
    OWNER = 3


class ERPS(Automaton):

    def __init__(self, *args, **kwargs):
        self.wtr_timeout = 0
        super(ERPS, self).__init__(args, kwargs)

    def block_port(self, port):
        self.debug(2, f"blocking port {port}")

    def unblock_port(self, port):
        self.debug(2, f"unblocking port {port}")

    def send_raps(self, msg_type, port):
        self.debug(2, f"sending RAPS {msg_type} to {port}")

    def parse_args(self,
                   port1,
                   port2,
                   port1_type=PORT_TYPE.NORMAL,
                   port2_type=PORT_TYPE.NORMAL,
                   guard_timeout=1,
                   wtr_timeout=1,
                   **kargs):
        Automaton.parse_args(self, **kargs)
        self.port1 = port1
        self.port2 = port2
        self.port1_type = port1_type
        self.port2_type = port2_type
        self.wtr_timeout = wtr_timeout
        self.wtr_guard = guard_timeout
        if port1_type == PORT_TYPE.OWNER or port2_type == PORT_TYPE.OWNER:
            self.node_type = PORT_TYPE.OWNER
        elif port1_type == PORT_TYPE.NEIGHBOR or port2_type == PORT_TYPE.NEIGHBOR:
            self.node_type = PORT_TYPE.NEIGHBOR
        else:
            self.node_type = PORT_TYPE.NORMAL

    @ATMT.state(initial=1)
    def INITIAL(self):
        self.debug(2, "Enter state INITIAL")
        block = None
        unblock = None
        # block RPL, unblock other
        block, unblock = self.port1, self.port2 \
            if self.node_type != PORT_TYPE.NORMAL and \
               self.port1_type != PORT_TYPE.NORMAL \
                   else self.port2, self.port1
        self.block_port(block)
        self.unblock_port(unblock)
        raise self.PENDING

    @ATMT.timeout(INITIAL, 1)
    def wtr_timer(self):
        print("Waited for timeout...")
        raise self.END()

    @ATMT.state()
    def IDLE(self):
        self.debug(2, "Enter state IDLE")

    @ATMT.state()
    def PROTECTION(self):
        self.debug(2, "Enter state PROTECTION")

    @ATMT.state()
    def MANUAL_SWITCH(self):
        self.debug(2, "Enter state MANUAL_SWITCH")

    @ATMT.state()
    def FORCED_SWITCH(self):
        self.debug(2, "Enter state FORCED_SWITCH")

    @ATMT.state()
    def PENDING(self):
        self.debug(2, "Enter state PENDING")

    @ATMT.action(wait_for_timeout)
    def on_nothing(self):
        print("Action on 'nothing' condition")


ERPS.graph()
# a = ERPS()
# a.run()
