# learning_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, June, 2015

# A frenetic app that learns host mac addresses as they arrive and installs "next hop" rules on each
# switch table using a fixed toplogy.

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

  # switches = { sw1 => [p1, p2, ...], sw2 => [ p1, ... ], }
  switches = {}

  # Like switches, but lists only internal ports
  switch_internal_ports = {}

  # Set of switches that form the core.  It's assumed no hosts are connected to these switches
  # except the Internet router which we pre-seed.  The L2 tables are stored on them.
  core_switches = set()

  # Like switches but returns a dictionary of destination switches to ports.  Though this data is part
  # of the agraph, the conversion of agraphs to networkx graphs turns the source and destination of 
  # the edges around (which is OK, because the graph is undirected)
  port_mappings = {}

  initial_config_complete = False

  ethernet_broadcast = "ff:ff:ff:ff:ff:ff"
  vlan = 1356

  # The dpid is a nasty 48-bit number, whereas the switch id is a nice label.  We use the latter
  # to communincate with Frenetic/OpenFlow, the former for logs and our own calculations and topo map 
  dpid_to_switch_dict = { }
  switch_to_dpid_dict = { }

  def __init__(self, topology_file = "gates_topology.dot"):
    frenetic.App.__init__(self) 

    print "---> Reading Topology from "+topology_file
    self.agraph = pgv.AGraph(topology_file)
    for sw in self.agraph.nodes():
      dpid = str(sw.attr['dpid'])
      self.dpid_to_switch_dict[ dpid ] = str(sw)
      self.switch_to_dpid_dict[ str(sw) ] = dpid
      if sw.attr['core']:
        self.core_switches.add (str(sw))

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

  # Return true if this port is connected to a host, and not just another switch
  def internal_port(self, switch, port_id):
    return port_id in self.switch_internal_ports[switch]

  def edge_port(self, switch, port_id):
    return not self.internal_port(switch, port_id)

  def hosts_on_switch(self, switch):
    return filter(lambda mac: self.hosts[mac][0] == switch, self.hosts)

  def learn(self, switch, port_id, mac):
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
 
  def broadcast_policy_for_switch_and_port(self, switch, port_id, include_vlan = True):
    flood_to_ports = [ p for p in self.switches[switch] if p != port_id ]
    output_actions = Union([  Mod(Location(Physical(p))) for p in flood_to_ports ])
    rules = [ 
      Test(Switch(self.switch_to_dpid(switch))), 
      Test(Location(Physical(port_id))), Test(EthDst(self.ethernet_broadcast))
    ]
    if include_vlan:
      rules.append( Test(Vlan(self.vlan)) )
    return Filter( And(rules) ) >> output_actions

  def core_next_hop_policy(self, switch, mac):
    (dest_switch, dest_port, next_hop_table) = self.hosts[mac]
    return Filter( \
      Test(Vlan(self.vlan)) & 
      Test(Switch(self.switch_to_dpid(switch))) & \
      Test(EthDst(mac)) \
    ) >> Mod(Location(Physical(next_hop_table[switch])))

  def uplink_port(self, switch):
    return 47 if switch.startswith("s_f") else 49

  def edge_from_learned_port_policy(self, switch, learned_port, mac):
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch))) & \
      Test(Location(Physical(learned_port))) & \
      Test(EthSrc(mac))
    ) >> Mod(Location(Physical(self.uplink_port(switch))))

  def to_learned_port_policy(self, switch, learned_port, mac):
    return Filter( \
      Test(Switch(self.switch_to_dpid(switch))) & \
      Test(Location(Physical(self.uplink_port(switch)))) & \
      Not(Test(EthSrc(mac))) & \
      Test(EthDst(mac)) 
    ) >> Mod(Location(Physical(learned_port)))

  def policy(self):
    all_policies = []

    for sw in self.switches:

      if sw in self.core_switches:
        # Broadcast rules are installed for all ports on core switches
        for p in self.switches[sw]:
          all_policies.append( self.broadcast_policy_for_switch_and_port(sw, p) )
        for mac in self.hosts:
          # Install an L2 rule for every host in the network.  
          all_policies.append( self.core_next_hop_policy( sw, mac ) )

      else:
        switch_hosts = self.hosts_on_switch(sw)
        # There is one broadcast rule on edge switches, coming in from the uplink port
        up = self.uplink_port(sw)
        all_policies.append( self.broadcast_policy_for_switch_and_port(sw, up, include_vlan = False) )
        for mac in switch_hosts:
          (_, dest_port, _) = self.hosts[mac]
          # Forward traffic from learned mac addresses to a core switch for dispatch
          all_policies.append( self.edge_from_learned_port_policy(sw, dest_port, mac) )
          # Forward traffic bound for a mac on this switch to the right port
          all_policies.append( self.to_learned_port_policy(sw, dest_port, mac)  )

    return Union(all_policies)

  # Send payload to all ports except the ingress port.  
  def flood_all_ports(self,switch, port_id, payload):
    # If we haven't got an official switch_up notice, we don't know the ports yet.  Just ignore.
    if switch not in self.switches:
      return
    flood_to_ports = [ p for p in self.switches[switch] if p != port_id ]
    output_actions = [ Output(Physical(p)) for p in flood_to_ports ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      print "Flooding from switch "+switch+" to "+str(flood_to_ports)
      self.pkt_out(self.switch_to_dpid(switch), payload, output_actions)
    else:
      print "No ports to flood broadcast from "+ str(port_id) + " on "+switch+" dropping packet."

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch(dpid): ports for dpid, ports in switches.items() }
 
      # We need to preload this because s_bdf is a core switch and macs are never learned here.
      # Besides, we don't want anyone trying to spoof it.  
      self.learn( 's_bdf', 1, 'd4:c9:ef:b2:1b:80' )

      # Load appropriate compiler options
      #self.config( CompilerOptions("empty", "Location < EthDst < EthSrc < Vlan < Switch", True, False, True) )

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
    if mac != self.ethernet_broadcast and self.edge_port(switch, port_id):
      if mac in self.hosts:
        (last_seen_switch, last_seen_port, _) = self.hosts[mac]
        if last_seen_switch != switch or last_seen_port != port_id:
          print "----> WARNING:  Dropping packet.  Apparent MAC spoofing of "+mac+" at "+switch+" / "+str(port_id)
          return
      else:
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
    # If port comes up, remove any learned macs on it (probably won't be any) 
    self.unlearn_mac_on_port(switch, port_id)

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

  # Don't remove switch info when it supposedly goes down - this happens all the time on Dell switches and it comes 
  # right back up.  
  def switch_down(self,dpid):
    switch = self.dpid_to_switch(dpid)
    print "Switch Down: "+switch

if __name__ == '__main__':
  print "\n\n\n*** Gates Learning Switch Application Begin"
  app = LearningSwitchApp(sys.argv[1])
  app.start_event_loop()