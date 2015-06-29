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

  def __init__(self):
    frenetic.App.__init__(self)  

  # If you use this to make a NetKAT policy, it's guaranteed to go into the Dell L2 table
  def l2_policy(self, switch_id, mac, port_id):
    return Filter( Test(Switch(switch_id)) & Test(Vlan(1356)) & Test(EthDst(mac)) ) >> Mod(Location(Physical(port_id)))

  basement_switches = set([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17])
  # Given a switch in the basement, which port on the eor switch goes to it?
  eor_to_basement_port = {
    2: 3, 3: 5, 4: 7, 5: 9,
    6: 11, 7: 13, 8: 15, 9: 17, 10: 19,
    11: 21, 12: 23, 13: 25, 14: 27, 15: 29
  }
  floor_switches = set([19, 20, 21, 22, 23])
  bdf_to_floor_port = { 19: 9, 20: 7, 21: 23, 22: 31, 23: 37 }
  syslab_switches = set([25, 26, 27, 28, 29, 30])
  syslab_eor_to_syslab_port = {
    25: 21, 26: 19, 27: 41, 28: 29, 29: 31, 30: 9
  }

  # Return true if this packet is coming from a host, and not just being routed internally
  # Note all these rules are installable in the L2 flow tables on the Dell switch
  def edge_packet(self, switch_id, port_id):
    return ((switch_id in self.basement_switches or switch_id in self.floor_switches or switch_id in self.syslab_switches) \
      and port_id < 47) \
      or (switch_id == 18 and port_id == 49) # Rhodes router is a special case.  

  def learn(self, switch_id, port_id, mac):
    print "Learning: "+mac
    if mac != self.ethernet_broadcast and mac not in self.hosts:
      self.hosts[mac] = (switch_id, port_id)
      self.unlearned_incoming_ports.discard( (switch_id, port_id) )

  # Return port number that packet mac on switch_id should travel out.  Assumes destination switch and port
  # is in hosts, as all learned macs are.  TODO: This is just a clever rearrangement of policies_for_mac
  # 
  def next_hop(self, switch_id, mac):
    print "Computing next hop for "+mac
    if mac not in self.hosts:
      # This effectively drops the packet.
      print "Not found in learning table, so don't know how to route packet.  Dropping."
      return 500

    (dest_switch_id, dest_port_id) = self.hosts[mac]
    if (switch_id == dest_switch_id):  # Then we're on the right switch, just output the right port
      return dest_port_id

    # If we're not in a star hub, move to the closest star hub
    if switch_id in self.basement_switches or switch_id in self.syslab_switches:
      return 49
    if switch_id in self.floor_switches:
      return 47

    # If we're in a star hub, move to the destination switch or one star-hub closer
    if dest_switch_id in self.basement_switches:
      if switch_id == 1:  # eor
        return self.eor_to_basement_port[dest_switch_id]
      else: # bdf or syslab_eor
        return 47

    if dest_switch_id in self.floor_switches:
      if switch_id == 18:  # bdf
        return self.bdf_to_floor_port[dest_switch_id]
      else: 
        return 47

    if dest_switch_id in self.syslab_switches:
      if switch_id == 24:  # syslab_eor
        return self.syslab_eor_to_syslab_port[dest_switch_id]
      else: 
        return 47

  def policies_for_mac(self, switch_id, port_id, mac):
    this_switch_policy = self.l2_policy(switch_id, mac, port_id)
    # Any switch communicating with this new mac should filter it to the top of the star first 
    basement_policies = [
      self.l2_policy(sw, mac, 49) for sw in self.basement_switches - set([switch_id])
    ]
    floor_policies = [
      self.l2_policy(sw, mac, 47) for sw in self.floor_switches - set([switch_id])
    ]
    syslab_policies = [
      self.l2_policy(sw, mac, 49) for sw in self.syslab_switches - set([switch_id])
    ]

    # Then distribution from the stars to the right one depends on where the mac is
    if switch_id in self.basement_switches:
      eor_policy = self.l2_policy(1, mac, self.eor_to_basement_port[switch_id])
      bdf_policy = self.l2_policy(18, mac, 47)
      syslab_eor_policy = self.l2_policy(24, mac, 47)
    elif switch_id in self.floor_switches:
      eor_policy = self.l2_policy(1, mac, 47)
      bdf_policy = self.l2_policy(18, mac, self.bdf_to_floor_port[switch_id])
      syslab_eor_policy = self.l2_policy(24, mac, 47)
    elif switch_id in self.syslab_switches:
      eor_policy = self.l2_policy(1, mac, 47)
      bdf_policy = self.l2_policy(18, mac, 47)
      syslab_eor_policy = self.l2_policy(24, mac, self.syslab_eor_to_syslab_port[switch_id])
    elif switch_id == 18:   # BDF, which hooks directly to Rhodes Internet Router
      eor_policy = self.l2_policy(1, mac, 47)
      bdf_policy = self.l2_policy(18, mac, 47)
      syslab_eor_policy = self.l2_policy(24, mac, 47)
    else:
      print "Packet from unexpected switch "+str(switch_id)+" port "+str(port_id)+" mac "+mac

    return Union([this_switch_policy] + 
      basement_policies + floor_policies + syslab_policies + 
      [eor_policy, bdf_policy, syslab_eor_policy])

  def send_to_controller(self):
    return Mod(Location(Pipe("learning_switch_app")))

  def incoming_unlearned_port_pred(self):
    return Or([Test(Switch(sw)) & Test(Location(Physical(p))) for (sw,p) in self.unlearned_incoming_ports])

  def all_incoming_ports(self):
    host_ports = set()
    for sw in self.switches:
      for p in self.switches[sw]:
        if self.edge_packet(sw, p):
          host_ports.add( (sw,p) )
    return host_ports

  def dest_mac_learned_pred(self):
    return Or([ Test(Vlan(1356)) & Test(EthDst(mac)) for mac in self.hosts])

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
    self.pkt_out(switch_id, payload, output_actions)

  def connected(self):
    def handle_current_switches(switches):
      self.switches = switches
      self.unlearned_incoming_ports = self.all_incoming_ports()
      self.update(self.policy())
    self.current_switches(callback=handle_current_switches) 

  def packet_in(self, switch_id, port_id, payload):
    pkt = packet.Packet(array.array('b', payload.data))
    p = get(pkt, 'ethernet')
    print "Received "+p.src+" -> ("+str(switch_id)+", "+str(port_id)+") -> "+p.dst
    mac = p.src
    if mac != self.ethernet_broadcast and mac not in self.hosts and self.edge_packet(switch_id, port_id):
      self.learn(switch_id, port_id, mac)
      self.update(self.policy())
    # TODO: Actually send the packet out to the new hop.  Don't assume the rules are there.
    # If this is a broadcast packet, send it to all destinations that aren't the ingress port.  
    if p.dst == self.ethernet_broadcast:
      self.flood_all_ports(switch_id, port_id, payload)
    else:
      # If it's a unicast packet, send it to the next hop
      self.pkt_out(switch_id, payload, [Output(Physical(self.next_hop(switch_id, p.dst)))])

  # TODO: Handle moves from one port to another ... maybe

app = LearningSwitchApp()
app.start_event_loop()