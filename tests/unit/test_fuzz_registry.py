from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from tlsocket.server_side.client_registry import ClientRegistry

IPS = st.sampled_from(["1.1.1.1", "2.2.2.2"])


class RegistryMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.reg = ClientRegistry(max_connections_per_ip=3)
        self.live = {}
        self.n = 0

    @rule(ip=IPS)
    def connect(self, ip):
        sock = f"sock{self.n}"
        self.n += 1
        if self.reg.try_reserve_ip_slot(sock, ip):
            self.live[sock] = ip

    @precondition(lambda self: bool(self.live))
    @rule(data=st.data())
    def disconnect(self, data):
        sock = data.draw(st.sampled_from(sorted(self.live)))
        self.reg.release_ip_slot(sock)
        del self.live[sock]

    @rule(ip=IPS)
    def failed_handshake(self, ip):
        self.reg.release_ip_slot("never-reserved")

    @invariant()
    def counter_matches_live_connections(self):
        expected = {}
        for ip in self.live.values():
            expected[ip] = expected.get(ip, 0) + 1
        assert dict(self.reg._ip_counts) == expected


TestRegistry = RegistryMachine.TestCase
    