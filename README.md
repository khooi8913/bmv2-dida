# p4-dns-amp-defense
Configuration steps/ notes: <br/>
1. Set `OP_MODE` register for each switch/ router (Edge = 0, Access/ TotR = 1)
2. Set `ROUTER_ID` register for each switch/ router
3. Current `THRESHOLD` is being set at 10 to ease the testing process.
4. TODO: CounterCheck process should be moved to the Ingress pipeline instead of being in the Egress pipeline, due to the fact that a packet's egress_spec cannot be modified after going through the PRE.
5. TODO: Modify forwarding rules for experiment purposes.