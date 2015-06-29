# broadcaster_app.py
# Craig Riecke, CoSciN Developer/Analyst, June, 2015

# THIS SCRIPT IS NO LONGER USED.  We had to merge the functionality into learning_switch
# because when a port makes an initial broadcast over the nrtwork, its mac must be learned.

# A frenetic app that floods all Ethernet broadcasts over all the switches and hosts in the 
# subnet.  Currently this is a fixed topology - later we'll learn it from discovery.  

# Note: I'm sure there's a nicer way to do this ...
import sys
sys.path.append('../frenetic/lang/python')
import frenetic
from frenetic.syntax import *

class BroadcasterApp(frenetic.App):
  client_id = "broadcaster"
  frenetic_http_host = "localhost"
  frenetic_http_port = "9000"
  switches = []
  vlan = 1356

  def __init__(self):
    frenetic.App.__init__(self)  

  # TODO: this is just a derived version of eor_to_basement_port, etc. and can be moved to a 
  # shared topology class 
  internal_ports = {
    1: [],
    18: [],
    24: []
  }
  
  def connected(self):
    def handle_current_switches(switches):
      self.switches = switches
      # After all the switches are taken care of, set the policy
      self.update(self.policy())

    self.current_switches(callback=handle_current_switches) 

  def packet_in(self, switch_id, port_id, payload):
    pass   

  def port_down(switch_id, port_id):
    pass

  def switch_down(switch_id, port_id):
    pass

  # TODO: Handle switch up's, which need the rules re-handed to them.

  # Create a policy that given a SwitchRef, floods all input to its ports.  We can't just use
  # the OpenFlow Pesudoport ALL because NetKAT doesn't allow it.  Yet, we don't need to supress
  # broadcasts back to the ingress port to prevent broadcast storms either.  Dell switches 
  # have source supression turned on by default to prevent this.  So take advantage of it.  That's the
  # only way we can make the broadcast routes go properly into the L2 Flow Table. 
  #
  # Note that it'd be nice to send broacast packets to the controller for learning, you can't do that
  # AND take advantage of the L2 table.  Too bad.  
  # 
  def flood_switch_policy(self, switch_id):
    def output_to_port(p):
      return Mod(Location(Physical(p)))

    actions = map(output_to_port, self.switches[switch_id])
    return Filter(Test(Switch(switch_id)) & Test(Vlan(self.vlan)) & Test(EthDst("ff:ff:ff:ff:ff:ff"))) >> Union(actions)

  def policy(self):
    all_actions = map(self.flood_switch_policy, self.switches)
    return Union(all_actions)

app = BroadcasterApp()
app.start_event_loop()