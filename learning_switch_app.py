# learning_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, June, 2015

# A frenetic app that learns host mac addresses as they arrive and installs "next hop" rules on each
# switch table.  Currently this is a fixed topology - later we'll learn it from discovery.  

# Note: I'm sure there's a nicer way to do this ...
import sys, array
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *
from ryu.lib.packet import packet, ethernet

def get(pkt,protocol):
  for p in pkt:
    if p.protocol_name == protocol:
      return p

class LearningSwitchApp(frenetic.App):
  client_id = "learning_switch"
  frenetic_http_host = "localhost"
  frenetic_http_port = "9000"

  # hosts = { mac1 => (sw1, port1), mac2 => (sw2, port2) }
  hosts = {}

  ethernet_broadcast = "ff:ff:ff:ff:ff:ff"
  vlan = 1356

  # This maps datapath id's from Dell to "nice" readable switch_id's 
  switch_labels = {
    1125908103288861: "s_eor",
    1125908103297789: "s_r1",
    1284990276223830: "s_r2",
    1284990276223836: "s_r3",
    1284990276224367: "s_r4",
    1284990276224415: "s_r5",
    1284990276223782: "s_r6",
    1284990276224424: "s_r7",
    1284990276224331: "s_r8",
    1284990276224418: "s_r9",
    1284990276224328: "s_r10",
    1284990276268919: "s_r11",
    1284990276224409: "s_r12",
    1284990276224322: "s_r13",
    1284990276224385: "s_r14",
    1284990276224421: "s_r15",
    1284990276224325: "s_r18",

    1125908108270984: "s_bdf",
    1125908103260016: "s_f1",
    1125908103297849: "s_f2",
    1125908103297804: "s_f3a",
    1125908103297660: "s_f3b",
    1125908103297765: "s_f4",

    1125908103289164: "s_lab_eor",
    1284990276224316: "s_lab_r3",
    1284990276223788: "s_lab_r99",
    1284990276220716: "s_lab_r5",
    1284990276223779: "s_lab_r6",
    1284990276223785: "s_lab_r7",
    1284990276223803: "s_lab_r0",

    1: "s_tplink"
  }
  label_switches = {v: k for k, v in switch_labels.items()}

  def __init__(self):
    frenetic.App.__init__(self)  

  def dpid_to_switch_id(self,dpid):
    return self.switch_labels[dpid]

  def switch_id_to_dpid(self,switch_id):
    return self.label_switches[switch_id]

  # If you use this to make a NetKAT policy, it's guaranteed to go into the Dell L2 table
  def l2_policy(self, switch_id, mac, port_id):
    return Filter( Test(Switch(self.switch_id_to_dpid(switch_id)) & Test(Vlan(self.vlan)) & Test(EthDst(mac)) ) >> Mod(Location(Physical(port_id)))

  basement_switches = { 
    "s_r1", "s_r2", "s_r3", "s_r4", "s_r5", "s_r6", "s_r7", "s_r8", "s_r9", 
    "s_r10", "s_r11", "s_r12", "s_r13", "s_r14", "s_r15", "s_r18"
  }
  # Given a switch in the basement, which port on the eor switch goes to it?  Note: r1, r11 and r18 are disconnected
  eor_to_basement_ports = {
    "s_r2": 3,   "s_r3": 5,   "s_r4": 7,   "s_r5": 9,
    "s_r6": 11,  "s_r7": 13,  "s_r8": 15,  "s_r9": 17,  "s_r10": 19,
    "s_r12": 23, "s_r13": 25, "s_r14": 27, "s_r15": 29
  }
  floor_switches = { "s_f1", "s_f2", "s_f3a", "s_f3b", "s_f4" }
  bdf_to_floor_ports = { "s_f1": 9, "s_f2": 17, "s_f3a": 23, "s_f3b": 31, "s_f4": 37 }
  lab_switches = { "s_lab_r3", "s_lab_r99", "s_lab_r5", "s_lab_r6", "s_lab_r7", "s_lab_r0" }
  lab_eor_to_lab_ports = {
    "s_lab_r3": 21, "s_lab_r99": 19, "s_lab_r5": 41, "s_lab_r6": 29, "s_lab_r7": 31, "s_lab_r0": 9
  }

  def switch_with_hosts(self, switch_id):
    "Return true if the given switch has hosts connected to it"
    return switch_id == "s_tplink" or \
      switch_id in self.basement_switches or \
      switch_id in self.floor_switches or \
      switch_id in self.lab_switches

  # Return true if this packet is coming from a host, and not just being routed internally
  def edge_packet(self, switch_id, port_id):
    # This is a special case of s_tplink.  Would it better if it were hooked to up to port 47, but...
    if switch_id == "s_lab_r0" and port_id == 34:
      return False
    if switch_id =='s_tplink' and port_id == 1:
      return False
    # Rhodes router is another special case, since it's hooked up to a tree switch
    if switch_id == 's_bdf' and port_id == 1:
      return True
    return self.switch_with_hosts(switch_id) and port_id < 47

  def learn(self, switch_id, port_id, mac):
    # Don't learn ethernet broadcast or hosts we've already learned before.  
    if mac != self.ethernet_broadcast and mac not in self.hosts:
      print "Learning: "+mac
      self.hosts[mac] = (switch_id, port_id)
      self.unlearned_incoming_ports.discard( (switch_id, port_id) )

  # Return port number that packet mac on switch_id should travel out.  Assumes destination switch and port
  # is in hosts, as all learned macs are.  TODO: This is just a clever rearrangement of policies_for_mac
  # Note: this is ONLY used for unicast packets, never broadcast
  def next_hop(self, switch_id, mac):
    print "Computing next hop for "+mac
    if mac not in self.hosts:
      # This effectively drops the packet.  It shouldn't happen if all hosts ask for the Mac address via ARP
      # first.   TODO: Send out ARP to all unlearned ports to see if any of them are the mac address.  But this is
      # hard because the responses must come back before the packet is released, and that's far from certain.   
      print "Not found in learning table, so don't know how to route packet.  Dropping."
      return 500

    (dest_switch_id, dest_port_id) = self.hosts[mac]
    if (switch_id == dest_switch_id):  # Then we're on the right switch, just output the right port
      return dest_port_id

    # If we're not in a star hub, move to the closest star hub
    if switch_id in self.basement_switches or switch_id in self.lab_switches:
      return 49
    if switch_id in self.floor_switches:
      return 47

    # If we're in a star hub, move to the destination switch or one star-hub closer
    if dest_switch_id in self.basement_switches:
      if switch_id == 's_eor':
        return self.eor_to_basement_ports[dest_switch_id]
      else: # bdf or lab_eor
        return 47

    if dest_switch_id in self.floor_switches:
      if switch_id == 's_bdf':
        return self.bdf_to_floor_ports[dest_switch_id]
      else: 
        return 47

    if dest_switch_id in self.lab_switches:
      if switch_id == 's_lab_eor':
        return self.lab_eor_to_lab_portsi[dest_switch_id]
      else: 
        return 47

    if dest_switch_id == 's_tplink':
      if switch_id == 's_bdf':
        return 45
      if switch_id == 's_lab_eor':
        return 9
      if switch_id == 's_lab_r0':
        return 34
      else:
        return 47

    # Should not happen.  Drop packet if we reach this point.  
    return 0

  # Generate a set of NetKAT policies for unicast packets to mac.  Doesn't include broadcasts.  
  def policies_for_mac(self, switch_id, port_id, mac):
    this_switch_policy = self.l2_policy(switch_id, mac, port_id)
    # Any switch communicating with this new mac should filter it to the top of the star first 
    basement_policies = [
      self.l2_policy(sw, mac, 49) for sw in self.basement_switches - set([switch_id])
    ]
    floor_policies = [
      self.l2_policy(sw, mac, 47) for sw in self.floor_switches - set([switch_id])
    ]
    lab_policies = [
      self.l2_policy(sw, mac, 49) for sw in self.lab_switches - set([switch_id])
    ]

    # Then distribution from the stars to the right one depends on where the mac is
    # Default policies
    eor_policy = self.l2_policy('s_eor', mac, 47)
    bdf_policy = self.l2_policy('s_bdf', mac, 47)
    lab_eor_policy = self.l2_policy('s_lab_eor', mac, 47)
    tplink_policy = self.l2_policy('s_tplink', mac, 1)

    if switch_id in self.basement_switches:
      eor_policy = self.l2_policy('s_eor', mac, self.eor_to_basement_ports[switch_id])
    elif switch_id in self.floor_switches:
      bdf_policy = self.l2_policy('s_bdf', mac, self.bdf_to_floor_ports[switch_id])
    elif switch_id in self.lab_switches:
      lab_eor_policy = self.l2_policy('s_lab_eor', mac, self.lab_eor_to_lab_ports[switch_id])
    elif switch_id == 's_bdf':   # BDF hooks directly to Rhodes Internet Router
      # Obviously there is no bdf policy, because the router is hooked up bdf.  But one is expected,
      # so we use the switch policy, and that'll get factored out later
      bdf_policy = this_switch_policy
    elif switch_id == 's_tplink':   # Another special case
      bdf_policy = self.l2_policy('s_bdf', mac, 45)
      lab_eor_policy = self.l2_policy('s_lab_eor', mac, 9)
      # The lab policies need to be rewritten to exclude s_lab_r0, which the tplink is connected to
      lab_policies = [
        self.l2_policy(sw, mac, 49) for sw in self.lab_switches - { "s_lab_r0" } 
      ]
      lab_policies = lab_policies + [ self.l2_policy("s_lab_r0", mac, 34) ]
      tplink_policy = this_switch_policy
    else:
      print "Packet from unexpected switch "+str(switch_id)+" port "+str(port_id)+" mac "+mac

    return Union([this_switch_policy] + 
      basement_policies + floor_policies + lab_policies + 
      [eor_policy, bdf_policy, lab_eor_policy, tplink_policy])

  def send_to_controller(self):
    return Mod(Location(Pipe("learning_switch_app")))

  def incoming_unlearned_port_pred(self):
    return Or([Test(Switch(self.switch_id_to_dpid(sw))) & Test(Location(Physical(p))) for (sw,p) in self.unlearned_incoming_ports])

  def all_incoming_ports(self):
    host_ports = set()
    for sw in self.switches:
      for p in self.switches[sw]:
        if self.edge_packet(sw, p):
          host_ports.add( (sw,p) )
    return host_ports

  def dest_mac_learned_pred(self):
    return Or([ Test(Vlan(self.vlan)) & Test(EthDst(mac)) for mac in self.hosts])

  def next_hop_policies(self):
    # This constructs m * s policies, where m = number of macs learned and s = number of switches
    return Union([self.policies_for_mac(switch_id, port_id, mac) for mac,(switch_id, port_id) in self.hosts.iteritems()])

  def policy(self):
    # The essence of the policy is:
    #
    #     if incoming port is not learned, then controller
    #        else if dest mac is learned then go to next hop
    #        else controller

    incoming_unlearned_port_pred = self.incoming_unlearned_port_pred()
    dest_mac_learned_pred = self.dest_mac_learned_pred()

    return incoming_unlearned_port_pred.ite(self.send_to_controller(),
      dest_mac_learned_pred.ite( self.next_hop_policies(), self.send_to_controller()
    ))

  # Send payload to all ports except the ingress port.  TODO: Only send it to ports on the spanning tree.
  def flood_all_ports(self,switch_id, port_id, payload):
    output_actions = [Output(Physical(p)) for p in self.switches[switch_id] if p != port_id ]
    # Only bother to send the packet out if there are ports to send it out on.
    if output_actions:
      self.pkt_out(self.switch_id_to_dpid(switch_id), payload, output_actions)

  def connected(self):
    def handle_current_switches(switches):
      # Convert ugly switch id to nice one
      self.switches = { self.dpid_to_switch_id(dpid): ports for dpid, ports in switches.items() }
      self.unlearned_incoming_ports = self.all_incoming_ports()
      self.update(self.policy())
    self.current_switches(callback=handle_current_switches) 

  def packet_in(self, dpid, port_id, payload):
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'ethernet')
    switch_id = self.dpid_to_switch_id(dpid)
    print "Received "+p.src+" -> ("+str(switch_id)+", "+str(port_id)+") -> "+p.dst
    mac = p.src
    if mac != self.ethernet_broadcast and mac not in self.hosts and self.edge_packet(switch_id, port_id):
      self.learn(switch_id, port_id, mac)
      self.update(self.policy())
    # If this is a broadcast packet, send it to all destinations that aren't the ingress port.  
    if p.dst == self.ethernet_broadcast:
      self.flood_all_ports(switch_id, port_id, payload)
    else:
      # If it's a unicast packet, send it to the next hop
      next_hop_port = self.next_hop(switch_id, p.dst)
      print "Sending out "+switch_id+"/"+str(next_hop_port)
      self.pkt_out(dpid, payload, [Output(Physical(next_hop_port))])

  def unlearn_mac_on_port(self, switch_id, port_id):
    orphaned_macs = filter(lambda mac: self.hosts[mac][0] == switch_id and self.hosts[mac][1] == port_id, self.hosts)
    for m in orphaned_macs:
      del self.hosts[m]

  def port_up(self,dpid, port_id):
    switch_id = self.dpid_to_switch_id(dpid)
    # If port comes up, remove any learned macs on it (probably won't be any) and
    # add it to the list of unlearned ports.
    self.unlearn_mac_on_port(switch_id, port_id)
    self.unlearned_incoming_ports.add( (switch_id, port_id) )

  def port_down(self,dpid, port_id):
    switch_id = self.dpid_to_switch_id(dpid)
    # If port goes down, remove any learned macs on it
    self.unlearn_mac_on_port(switch_id, port_id)

  def switch_up(self,dpid,ports):
    switch_id = self.dpid_to_switch_id(dpid)
    print "Switch Up: "+switch_id
    # If we've seen this switch before, just return.  Otherwise add the ports to unlearned. 
    if switch_id in self.switches:
      return
    for port_id in ports:
      if self.edge_packet(switch_id, port_id):
        self.unlearned_incoming_ports.add( (switch_id, port_id) )

  def switch_down(self,dpid,ports):
    switch_id = self.dpid_to_switch_id(dpid)
    print "Switch Down: "+switch_id

  # Currently if switches come up or down, just note them in the log.  Unlearning their details would be a waste
  # in a network with no loops because the edges connected to that switch won't be able to communicate anyway.  
app = LearningSwitchApp()
app.start_event_loop()