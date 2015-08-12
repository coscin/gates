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

  def preload_learned_unlearned(self, switch, external_ports, learned_ports):
    # Only for testing 

    # This looks dumb, but I just want a unique two-digit number to represent a switch for testing
    switch_index = 0
    for this_sw in self.switches:
      if this_sw == switch:
        sw = self.switches[switch]
        switch_number = switch_index
      switch_index += 1

    for port_id in external_ports:
      if port_id not in sw:
        sw.append(port_id)

      if port_id in learned_ports:
        # Assume that the mac at switch s, port p is s:00:00:00:00:00:p.  Ignore hex nonsense.
        fake_mac = ('%02d' % switch_number) + ":00:00:00:00:" + ('%02d' % port_id)
        self.learn(switch, port_id, fake_mac)
      else:
        self.unlearned_incoming_ports.add( (switch, port_id) )

  def capacity_testing(self):
    # Only for testing
    print "---> Calculating capacity testing data"
    for switch_id in self.switches:
      external_ports = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
      learned_ports = set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
      self.preload_learned_unlearned(switch_id, external_ports, learned_ports)
    print "---> Installing in switch"
    self.update(self.policy())
    print "---> Done"

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

  def unlearned_incoming_ports_in_switch(self, switch):
    return map(lambda swp: swp[1], filter(lambda swp: swp[0]==switch, self.unlearned_incoming_ports))

  def l2_policy(self, switch, mac, port_id):
    # If you use this to make a NetKAT policy, it's guaranteed to go into the Dell L2 table.  However,
    # you have to add the unlearned and internal ports clause so that extra unneeded rules are not added to ACL.  They
    # actually get optimized out in flow table generation
    ignore_ports = self.unlearned_incoming_ports_in_switch(switch) 
    ignore_ports += self.switch_internal_ports[switch]
    ignore_preds = [ Test(Location(Physical(p))) for p in ignore_ports ]
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch))) & \
      Test(Vlan(self.vlan)) & \
      Test(EthDst(mac)) & \
      Not(Or(ignore_preds)) \
    ) >> Mod(Location(Physical(port_id)))

  # Return true if this port is connected to a host, and not just another switch
  def edge_port(self, switch, port_id):
    return port_id not in self.switch_internal_ports[switch]

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

  # Generate a set of NetKAT policies for unicast packets to mac.  Doesn't include broadcasts. 
  # Assumes that we've already "learned" the port and have computed shortest paths, etc.   
  def policies_for_mac(self, mac):
    (dest_switch, dest_port, next_hop_table) = self.hosts[mac]
    return [ self.l2_policy(next_sw, mac, next_hop_table[next_sw]) for next_sw in next_hop_table ]

  def incoming_unlearned_port_policy(self, switch, port_id):
    # This is required for proper optimization.   See l2_policy for reasons why.
    ignore_mac_preds = [ Test(EthDst(mac)) for mac in self.hosts ]
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch))) & \
      Test(Location(Physical(port_id))) & \
      Not(Or(ignore_mac_preds))
    ) >> Mod(Location(Pipe("learning_switch_app")))

  def broadcast_policy_for_switch_and_port(self, switch, port_id):
    flood_to_ports = [ p for p in self.switches[switch] if p != port_id ]
    output_actions = Union([  Mod(Location(Physical(p))) for p in flood_to_ports ])
    return Filter(Test(EthDst(self.ethernet_broadcast)) & Test(Switch(self.switch_to_dpid(switch))) & Test(Location(Physical(port_id)))) >> output_actions

  def policy(self):
    all_policies = []
    for sw in self.switches:
      for p in self.switches[sw]:
        if (sw,p) in self.unlearned_incoming_ports:
          all_policies.append( self.incoming_unlearned_port_policy(sw, p) )
        else:
          all_policies.append( self.broadcast_policy_for_switch_and_port(sw, p) )

    for mac in self.hosts:
      all_policies += self.policies_for_mac(mac)

    return Union(all_policies)

  # Send payload to all ports except the ingress port.  
  def flood_all_ports(self,switch, port_id, payload):
    # If we haven't got an official switch_up notice, we don't know the ports yet.  Just ignore.
    if switch not in self.switches:
      return
    flood_to_ports = [ p for p in self.switches[switch] if p != port_id ]
    print "Flooding from switch "+switch+" to "+str(flood_to_ports)
    output_actions = [ Output(Physical(p)) for p in flood_to_ports ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.switch_to_dpid(switch), payload, output_actions)


  def all_incoming_ports(self):
    host_ports = set()
    for sw in self.switches:
      for p in self.switches[sw]:
        if self.edge_port(sw, p):
          host_ports.add( (sw,p) )
    return host_ports

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
      self.unlearned_incoming_ports = self.all_incoming_ports()
      # Uncomment the following to pre-seed learned macs for capacity testing
      # self.capacity_testing()
      print "Connected to Frenetic - Switches: "+str(self.switches)
      self.update(self.policy())
      self.initial_config_complete = True
    # If Frenetic went down, it'll call connected() when it comes back up.  In that case, just 
    # resend the current policies
    if self.initial_config_complete:
      self.update(self.policy())
    else:
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
      # If it's a unicast packet, send it to the next hop. 
      if p.dst not in self.hosts:
        # It's possible that the mac was in the source's ARP cache, but it hasn't been learned yet.
        # In that case, simply flood it out the switch.  The hope is the mac will respond with a unicast
        # packet itself, which will then be learned, and will prevent this in the future.
        self.flood_all_ports(switch, port_id, payload)
      else:
        (dest_switch, dest_port, next_hop_table) = self.hosts[p.dst]
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

if __name__ == '__main__':
  print "\n\n\n*** Gates Learning Switch Application Begin"
  app = LearningSwitchApp()
  app.start_event_loop()