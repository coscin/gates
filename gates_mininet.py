# Model of Gates Network for Mininet
# Craig Riecke, CoSciN Developer/Analyst, June, 2015
#
# To make this work:
# - You need to be at Mininet > 2.2, which you should build from source if on Ubuntu 14.04 (the
#   latest dpkg is Mininet 2.1).  This will make the links use the right ports instead of 
#   sequentially renumbering them
# - You need vlan package, via "sudo apt-get install vlan"
# - You also need DHCP server and client, packages udhcpd and udhcpc 
# - You NEED OpenVSwitch = 2.1.  Install this from mininet - util/install.sh -V 2.1.3  
#   - Version 2.0.2, the one that comes in Ubuntu 14.04, has a 
#   bug which sends a truncated packet with packet_in, but with buffer_id=-1 (meaning no buffer)
#   Since you don't have all the data, it's impossible to send out the correct data in packet_out.
#   This really affects DHCP. 
#   - Version 2.3 installs a Table Miss rule to drop all packets, and you can't get rid of it.
#   Dell switches are configured to Table-Miss to the controller, and that's REQUIRED because of
#   the insane implementation of ACL and L2/L3 tables.  So your scripts won't work here.   

import re
import sys
from networkx import *
import pygraphviz as pgv

# Mininet imports
from mininet.log import lg, info, error, debug, output
from mininet.util import quietRun
from mininet.node import Host, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.net import Mininet


# Mercilessly copied from https://github.com/mininet/mininet/blob/master/examples/vlanhost.py
#
class VLANHost( Host ):
  "Host connected to VLAN interface"

  def config( self, vlan=100, **params ):
    """Configure VLANHost according to (optional) parameters:
       vlan: VLAN ID for default interface"""

    r = super( VLANHost, self ).config( **params )

    intf = self.defaultIntf()
    # remove IP from default, "physical" interface
    self.cmd( 'ifconfig %s inet 0' % intf )
    # create VLAN interface
    self.cmd( 'vconfig add %s %d' % ( intf, vlan ) )
    # assign the host's IP to the VLAN interface
    self.cmd( 'ifconfig %s.%d inet %s' % ( intf, vlan, params['ip'] ) )
    # update the intf name and host's intf map
    newName = '%s.%d' % ( intf, vlan )
    # update the (Mininet) interface to refer to VLAN interface name
    intf.name = newName
    # add VLAN interface to host's name to intf map
    self.nameToIntf[ newName ] = intf

    return r

# DHCP server functions and data

DNSTemplate = """
start   128.253.154.100
end     128.253.154.250
option  subnet  255.255.255.0
option  domain  local
option  lease 3600  # seconds
"""

def makeDHCPconfig( filename, intf, gw, dns ):
  "Create a DHCP configuration file"
  config = (
    'interface %s' % intf,
    DNSTemplate,
    'option router %s' % gw,
    'option dns %s' % dns,
    '' )
  with open( filename, 'w' ) as f:
    f.write( '\n'.join( config ) )

def startDHCPserver( host, gw, dns ):
  "Start DHCP server on host with specified DNS server"
  info( '* Starting DHCP server on', host, 'at', host.IP(), '\n' )
  dhcpConfig = '/tmp/%s-udhcpd.conf' % host
  makeDHCPconfig( dhcpConfig, host.defaultIntf(), gw, dns )
  host.cmd( 'udhcpd -f', dhcpConfig,
            '1>/tmp/%s-dhcp.log 2>&1  &' % host )

def start(ip="127.0.0.1",port=6633):

    ctrlr = lambda n: RemoteController(n, ip=ip, port=port, inNamespace=False)
    net = Mininet(switch=OVSSwitch, controller=ctrlr, autoStaticArp=False)
    c1 = net.addController('c1')

    gates_agraph = pgv.AGraph("simplified_gates_topology.dot")
    for sw in gates_agraph.nodes():
        net.addSwitch(sw, dpid = hex( int(sw.attr['dpid']) )[2:])

    for link in gates_agraph.edges():
        (src_switch, dst_switch) = link
        net.addLink(src_switch, dst_switch, int(link.attr['src_port']), int(link.attr['dport']) )

    # Only one host and an Internet Router disguised as a host for now (because it's not part of the OF network)
    h0 = net.addHost('h0', cls=VLANHost, mac='d4:c9:ef:b2:1b:80', ip='128.253.154.1', vlan=1356)
    net.addLink("s_bdf", h0, 1, 0)

    # To test DHCP functionality, ucnomment this line and comment out the fixed IP line.  Then when mininet
    # starts you issue:
    #   mininet> h1 dhclient -v -d -1 h1-eth0.1356
    # and make sure it gets its IP by going through all protocol steps.
    #h1 = net.addHost('h1', cls=VLANHost, mac='00:00:01:00:00:11', ip='0.0.0.0', vlan=1356)
    h1 = net.addHost('h1', cls=VLANHost, mac='00:00:01:00:00:11', ip='128.253.154.100', vlan=1356)
    net.addLink("s_f3a", h1, 32, 0)

    # Client for tplink, since it's a little weird
    # h2 = net.addHost('h2', cls=VLANHost, mac='00:00:01:00:00:12', ip='128.253.154.101', vlan=1356)
    # net.addLink("s_tplink", h2, 2, 0)

    h3 = net.addHost('h3', cls=VLANHost, mac='00:00:01:00:00:13', ip='128.253.154.102', vlan=1356)
    net.addLink("s_lab_r6", h3, 1, 0)

    # MAC spoofing attempt of h3
    h4 = net.addHost('h4', cls=VLANHost, mac='00:00:01:00:00:13', ip='128.253.154.102', vlan=1356)
    net.addLink("s_lab_r6", h4, 2, 0)

    ###### Start of static Mininet epilogue ######
    # Set up logging etc.
    lg.setLogLevel('info')
    lg.setLogLevel('output')

    # Start the network
    net.start()
    # Start the DHCP server on Internet Router.  This will actually be a DHCP proxy in the real setup.  
    #startDHCPserver( h0, gw='128.253.154.1', dns='8.8.8.8')


    # Enter CLI mode
    output("Network ready\n")
    output("Press Ctrl-d or type exit to quit\n")
    CLI(net)
    # net.stop()

start()