# learning_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, June, 2015

# A frenetic app that learns host mac addresses as they arrive and installs "next hop" rules on each
# switch table.  Currently this is a fixed topology - later we'll learn it from discovery.  

# Note: I'm sure there's a nicer way to do this ...
import sys, array
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
from ryu.lib.packet import packet, ethernet, vlan, arp
import networkx as nx
import pygraphviz as pgv

def get(pkt,protocol):
  for p in pkt:
    if p.protocol_name == protocol:
      return p

class LearningSwitchApp(frenetic.App):
  client_id = "learning_switch"
  frenetic_http_host = "localhost"
  frenetic_http_port = "9000"

  # hosts = { mac1 => (sw1, port1, hoplist1), mac2 => (sw2, port2, hoplist2), ... }
  # where hoplistn is the next_hop table for each switch: [(sw1, port1), (sw2, port2), etc.] 
  hosts = {}

  # shortest_paths = { hostmac1 => {sw1 => [sw1, hop1, hop2, host], sw2 => [sw2, hop1, hop2, host]}, hostmac2 => }
  shortest_paths = {}

  # switches = { sw1 => [p1, p2, ...], sw2 => [ p1, ... ], }
  switches = {}

  # Like switches, but lists only internal ports
  switch_internal_ports = {}

  # Like switches but returns a dictionary of destination switches to ports.  Though this data is part
  # of the agraph, the conversion of agraphs to networkx graphs turns the source and destination of 
  # the edges around (which is OK, because the graph is undirected)
  port_mappings = {}

  # unlearned_incoming_ports = { (sw1, port1), (sw2, port2), ... }
  unlearned_incoming_ports = {}

  initial_config_complete = False

  ethernet_broadcast = "ff:ff:ff:ff:ff:ff"
  vlan = 1356

  # The dpid is a nasty 48-bit number, whereas the switch id is a nice label.  We use the latter
  # to communincate with Frenetic/OpenFlow, the former for logs and our own calculations and topo map 
  dpid_to_switch_dict = { }
  switch_to_dpid_dict = { }

  def __init__(self):
    frenetic.App.__init__(self) 

    print "---> Reading Topology"
    self.agraph = pgv.AGraph("gates_topology.dot")
    for sw in self.agraph.nodes():
      dpid = str(sw.attr['dpid'])
      self.dpid_to_switch_dict[ dpid ] = str(sw)
      self.switch_to_dpid_dict[ str(sw) ] = dpid

    # It's faster to denormalize this now
    print "---> Remembering internal ports"
    self.switch_internal_ports = { sw: set([]) for sw in self.switch_to_dpid_dict }
    for e in self.agraph.edges():
      source_sw = str(e[0])
      dest_sw = str(e[1])
      source_port = int(e.attr["src_port"])
      dest_port = int(e.attr["dport"])
      self.switch_internal_ports[ source_sw ].add( source_port )
      if source_sw not in self.port_mappings:
        self.port_mappings[source_sw] = {}
      self.port_mappings[source_sw][dest_sw] = source_port
      self.switch_internal_ports[ dest_sw ].add( dest_port )
      if dest_sw not in self.port_mappings:
        self.port_mappings[dest_sw] = {}
      self.port_mappings[dest_sw][source_sw] = dest_port

    print "---> Calculating spanning tree"
    nxgraph = nx.from_agraph(self.agraph)
    self.nx_topo = nx.minimum_spanning_tree(nxgraph)

  def dpid_to_switch(self,dpid):
    # If ITSG introduces a new switch that's not in our topo map yet, be tolerant of it (even if it
    # has no edges yet, so it can't route anything)
    if str(dpid) not in self.dpid_to_switch_dict:
      return "s_"+str(dpid)
    return self.dpid_to_switch_dict[ str(dpid) ]

  def switch_to_dpid(self,switch):
    if switch not in self.switch_to_dpid_dict:
      return int(switch[2:])
    return int(self.switch_to_dpid_dict[switch])

  # If you use this to make a NetKAT policy, it's guaranteed to go into the Dell L2 table
  def l2_policy(self, switch, mac, port_id):
    return Filter( Test(Switch(self.switch_to_dpid(switch))) & Test(Vlan(self.vlan)) & Test(EthDst(mac)) ) >> Mod(Location(Physical(port_id)))

  # basement_switches = { 
  #   "s_r1", "s_r2", "s_r3", "s_r4", "s_r5", "s_r6", "s_r7", "s_r8", "s_r9", 
  #   "s_r10", "s_r11", "s_r12", "s_r13", "s_r14", "s_r15", "s_r18"
  # }
  # # Given a switch in the basement, which port on the eor switch goes to it?  Note: r1, r11 and r18 are disconnected
  # eor_to_basement_ports = {
  #   "s_r2": 3,   "s_r3": 5,   "s_r4": 7,   "s_r5": 9,
  #   "s_r6": 11,  "s_r7": 13,  "s_r8": 15,  "s_r9": 17,  "s_r10": 19,
  #   "s_r12": 23, "s_r13": 25, "s_r14": 27, "s_r15": 29, "s_r16": 31
  # }
  # floor_switches = { "s_f1", "s_f2", "s_f3a", "s_f3b", "s_f4" }
  # bdf_to_floor_ports = { "s_f1": 9, "s_f2": 17, "s_f3a": 23, "s_f3b": 31, "s_f4": 37 }
  # lab_switches = { "s_lab_r3", "s_lab_r99", "s_lab_r5", "s_lab_r6", "s_lab_r7", "s_lab_r0" }
  # lab_eor_to_lab_ports = {
  #   "s_lab_r3": 21, "s_lab_r99": 19, "s_lab_r5": 41, "s_lab_r6": 29, "s_lab_r7": 31, "s_lab_r0": 9
  # }

  # def switch_with_hosts(self, switch):
  #   "Return true if the given switch has hosts connected to it"
  #   return switch == "s_tplink" or \
  #     switch in self.basement_switches or \
  #     switch in self.floor_switches or \
  #     switch in self.lab_switches

  # Return true if this port is connected to a host, and not just another switch
  def edge_port(self, switch, port_id):
    return port_id not in self.switch_internal_ports[switch]

    # # This is a special case of s_tplink.  Would it better if it were hooked to up to port 47, but...
    # if switch == "s_lab_r0" and port_id == 34:
    #   return False
    # if switch =='s_tplink' and port_id == 1:
    #   return False
    # # Rhodes router is another special case, since it's hooked up to a tree switch
    # if switch == 's_bdf' and port_id == 1:
    #   return True
    # return self.switch_with_hosts(switch) and port_id < 47

  def learn(self, switch, port_id, mac):
    # Don't learn ethernet broadcast or hosts we've already learned before.  
    if mac == self.ethernet_broadcast or mac in self.hosts:
      return

    print "Learning: "+mac+" attached to ( "+switch+", "+str(port_id)+" )"
    # Compute next hop table: from each switch, which port do you need to go next to get to destination?
    self.nx_topo.add_node(mac)
    self.nx_topo.add_edge(switch, mac)
    # Note we don't need a mapping from mac to switch because we never see packets going INTO a host
    self.port_mappings[switch][mac] = port_id

    # Return shortest paths from each source in the graph to mac in the form [src, hop1, hop2, ..., mac]
    spaths = nx.shortest_path(self.nx_topo, None, mac, None)
    next_hop_table = { }
    for sw in self.switches:
      # If there are no paths from sw, just skip it
      if sw in spaths:
        next_sw = spaths[sw][1]  # The next hop switch along the shortest path from sw to mac.  Possble that dest = mac
        next_hop_table[sw] = self.port_mappings[sw][next_sw]

    self.hosts[mac] = (switch, port_id, next_hop_table)
    self.unlearned_incoming_ports.discard( (switch, port_id) )


  # # Return port number that packet mac on switch should travel out.  Assumes destination switch and port
  # # is in hosts, as all learned macs are.  TODO: This is just a clever rearrangement of policies_for_mac
  # # Note: this is ONLY used for unicast packets, never broadcast
  # def next_hop(self, switch, mac):
  #   print "Computing next hop for "+mac
  #   if mac not in self.hosts:
  #     # This effectively drops the packet.  It shouldn't happen if all hosts ask for the Mac address via ARP
  #     # first.   TODO: Send out ARP to all unlearned ports to see if any of them are the mac address.  But this is
  #     # hard because the responses must come back before the packet is released, and that's far from certain.   
  #     print "Not found in learning table, so don't know how to route packet.  Dropping."
  #     return 500

  #   (dest_switch, dest_port_id) = self.hosts[mac]
  #   if (switch == dest_switch):  # Then we're on the right switch, just output the right port
  #     return dest_port_id

  #   # If we're not in a star hub, move to the closest star hub
  #   if switch in self.basement_switches or switch in self.lab_switches:
  #     return 49
  #   if switch in self.floor_switches:
  #     return 47

  #   # If we're in a star hub, move to the destination switch or one star-hub closer
  #   if dest_switch in self.basement_switches:
  #     if switch == 's_eor':
  #       return self.eor_to_basement_ports[dest_switch]
  #     else: # bdf or lab_eor
  #       return 47

  #   if dest_switch in self.floor_switches:
  #     if switch == 's_bdf':
  #       return self.bdf_to_floor_ports[dest_switch]
  #     else: 
  #       return 47

  #   if dest_switch in self.lab_switches:
  #     if switch == 's_lab_eor':
  #       return self.lab_eor_to_lab_portsi[dest_switch]
  #     else: 
  #       return 47

  #   if dest_switch == 's_tplink':
  #     if switch == 's_bdf':
  #       return 45
  #     if switch == 's_lab_eor':
  #       return 9
  #     if switch == 's_lab_r0':
  #       return 34
  #     else:
  #       return 47

  #   # Should not happen.  Drop packet if we reach this point.  
  #   return 0

  # Generate a set of NetKAT policies for unicast packets to mac.  Doesn't include broadcasts. 
  # Assumes that we've already "learned" the port and have computed shortest paths, etc.   
  def policies_for_mac(self, mac):
    if mac not in self.hosts:
      print "ERROR: "+mac+" has not been learned.  Packet being dropped."
      return drop() 

    (dest_switch, dest_port, next_hop_table) = self.hosts[mac]
    print next_hop_table
    return Union([ self.l2_policy(next_sw, mac, next_hop_table[next_sw]) for next_sw in next_hop_table ] )

  # def policies_for_mac(self, switch, port_id, mac):
  #   this_switch_policy = self.l2_policy(switch, mac, port_id)
  #   # Any switch communicating with this new mac should filter it to the top of the star first 
  #   basement_policies = [
  #     self.l2_policy(sw, mac, 49) for sw in self.basement_switches - set([switch])
  #   ]
  #   floor_policies = [
  #     self.l2_policy(sw, mac, 47) for sw in self.floor_switches - set([switch])
  #   ]
  #   lab_policies = [
  #     self.l2_policy(sw, mac, 49) for sw in self.lab_switches - set([switch])
  #   ]

  #   # Then distribution from the stars to the right one depends on where the mac is
  #   # Default policies
  #   eor_policy = self.l2_policy('s_eor', mac, 47)
  #   bdf_policy = self.l2_policy('s_bdf', mac, 47)
  #   lab_eor_policy = self.l2_policy('s_lab_eor', mac, 47)
  #   tplink_policy = self.l2_policy('s_tplink', mac, 1)

  #   if switch in self.basement_switches:
  #     eor_policy = self.l2_policy('s_eor', mac, self.eor_to_basement_ports[switch])
  #   elif switch in self.floor_switches:
  #     bdf_policy = self.l2_policy('s_bdf', mac, self.bdf_to_floor_ports[switch])
  #   elif switch in self.lab_switches:
  #     lab_eor_policy = self.l2_policy('s_lab_eor', mac, self.lab_eor_to_lab_ports[switch])
  #   elif switch == 's_bdf':   # BDF hooks directly to Rhodes Internet Router
  #     # Obviously there is no bdf policy, because the router is hooked up bdf.  But one is expected,
  #     # so we use the switch policy, and that'll get factored out later
  #     bdf_policy = this_switch_policy
  #   elif switch == 's_tplink':   # Another special case
  #     bdf_policy = self.l2_policy('s_bdf', mac, 45)
  #     lab_eor_policy = self.l2_policy('s_lab_eor', mac, 9)
  #     # The lab policies need to be rewritten to exclude s_lab_r0, which the tplink is connected to
  #     lab_policies = [
  #       self.l2_policy(sw, mac, 49) for sw in self.lab_switches - { "s_lab_r0" } 
  #     ]
  #     lab_policies = lab_policies + [ self.l2_policy("s_lab_r0", mac, 34) ]
  #     tplink_policy = this_switch_policy
  #   else:
  #     print "Packet from unexpected switch "+str(switch)+" port "+str(port_id)+" mac "+mac

  #   return Union([this_switch_policy] + 
  #     basement_policies + floor_policies + lab_policies + 
  #     [eor_policy, bdf_policy, lab_eor_policy, tplink_policy])

  def send_to_controller(self):
    return Mod(Location(Pipe("learning_switch_app")))

  def incoming_unlearned_port_pred(self):
     return Or([Test(Switch(self.switch_to_dpid(sw))) & Test(Location(Physical(p))) for (sw,p) in self.unlearned_incoming_ports])

  def all_incoming_ports(self):
    host_ports = set()
    for sw in self.switches:
      for p in self.switches[sw]:
        if self.edge_port(sw, p):
          host_ports.add( (sw,p) )
    return host_ports

  def dest_mac_learned_pred(self):
    return Or([ Test(Vlan(self.vlan)) & Test(EthDst(mac)) for mac in self.hosts])

  def next_hop_policies(self):
    # This constructs m * s policies, where m = number of macs learned and s = number of switches
    return Union([ self.policies_for_mac(mac) for mac in self.hosts ])

  def policy(self):
    # The essence of the policy is:
    #
    #     if incoming port is not learned, then controller
    #        else if dest mac is broadcast, then broadcast to all ports except ingress
    #        else if dest mac is learned then go to next hop
    #        else controller

    incoming_unlearned_port_pred = self.incoming_unlearned_port_pred()
    dest_mac_learned_pred = self.dest_mac_learned_pred()

    return incoming_unlearned_port_pred.ite(self.send_to_controller(),
      dest_mac_learned_pred.ite( self.next_hop_policies(), self.send_to_controller()
    ))

  # Send payload to all ports except the ingress port.  TODO: Only send it to ports on the spanning tree.
  def flood_all_ports(self,switch, port_id, payload):
    # If we haven't got an official switch_up notice, we don't know the ports yet.  Just ignore.
    if switch not in self.switches:
      return
    # TODO: Rip this code out.  Currently the Rhodes Internet Router sends out a lot of
    # broadcast ARP packets for IP's/macs that no longer exist (or that exist on other
    # networks).  This causes so much noise in the logs and I suspect it may be causing s_bdf
    # to drop packets.  So drop them for now.  And since there's no buffering on Dell switches,
    # we don't even need to explicitly drop it.  Just don't send any actions back. 
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'ethernet')
    # If this is VLan packet, get ethernet type from emebdded header instead
    ethertype = get(pkt, 'vlan').ethertype if (p.ethertype == 0x8100) else p.ethertype
    #if switch == 's_bdf' and port_id == 1 and ethertype == 0x806:
    #  arp_p = get(pkt, 'arp')
    #  print "Arp Packet with opcode "+str(arp_p.opcode)+" dropped"
    #  return
    flood_to_ports = [ p for p in self.switches[switch] if p != port_id ]
    print "Flooding from switch "+switch+" to "+str(flood_to_ports)
    output_actions = [ Output(Physical(p)) for p in flood_to_ports ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.switch_to_dpid(switch), payload, output_actions)

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
      self.unlearned_incoming_ports = self.all_incoming_ports()
      print "Connected to Frenetic - Switches: "+str(self.switches)
      self.update(self.policy())
      self.initial_config_complete = True
    self.current_switches(callback=handle_current_switches) 

  def packet_in(self, dpid, port_id, payload):
    # If switches haven't been read in yet, don't process packet.
    if not self.initial_config_complete:
      print "Packets received before initialization, dropping" 
      return
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'ethernet')
    switch = self.dpid_to_switch(dpid)
    print "Received "+p.src+" -> ("+str(switch)+", "+str(port_id)+") -> "+p.dst
    mac = p.src
    if mac != self.ethernet_broadcast and mac not in self.hosts and self.edge_port(switch, port_id):
      self.learn(switch, port_id, mac)
      self.update(self.policy())
    # If this is a broadcast packet, send it to all destinations that aren't the ingress port.  
    if p.dst == self.ethernet_broadcast:
      self.flood_all_ports(switch, port_id, payload)
    else:
      # If it's a unicast packet, send it to the next hop
      (dest_switch, dest_port, next_hop_table) = self.hosts[mac]
      next_hop_port = next_hop_table[switch]
      print "Sending out "+switch+"/"+str(next_hop_port)
      self.pkt_out(dpid, payload, [Output(Physical(next_hop_port))])

  def unlearn_mac_on_port(self, switch, port_id):
    orphaned_macs = filter(lambda mac: self.hosts[mac][0] == switch and self.hosts[mac][1] == port_id, self.hosts)
    for m in orphaned_macs:
      del self.hosts[m]

  def port_up(self,dpid, port_id):
    switch = self.dpid_to_switch(dpid)
    # If port comes up, remove any learned macs on it (probably won't be any) and
    # add it to the list of unlearned ports.
    self.unlearn_mac_on_port(switch, port_id)
    self.unlearned_incoming_ports.add( (switch, port_id) )

  def port_down(self,dpid, port_id):
    switch = self.dpid_to_switch(dpid)
    # If port goes down, remove any learned macs on it
    self.unlearn_mac_on_port(switch, port_id)

  def switch_up(self,dpid,ports):
    switch = self.dpid_to_switch(dpid)
    print "Switch Up: "+switch
    # If we've seen this switch before, just return.  Otherwise add the ports to unlearned. 
    if switch in self.switches:
      return
    self.switches[switch] = ports
    print "Updated Switches: "+str(self.switches)
    for port_id in ports:
      if self.edge_port(switch, port_id):
        self.unlearned_incoming_ports.add( (switch, port_id) )

  # Don't remove switch info when it supposedly goes down - this happens all the time on Dell switches and it comes 
  # right back up.  
  def switch_down(self,dpid):
    switch = self.dpid_to_switch(dpid)
    print "Switch Down: "+switch

print "\n\n\n*** Gates Learning Switch Application Begin"
app = LearningSwitchApp()
app.start_event_loop()