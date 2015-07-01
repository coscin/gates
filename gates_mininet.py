# Model of Gates Network for Mininet
# Craig Riecke, CoSciN Developer/Analyst, June, 2015
#
# To make this work:
# - You need to be at Mininet > 2.2, which you should build from source if on Ubuntu 14.04 (the
#   latest dpkg is Mininet 2.1).  This will make the links use the right ports instead of 
#   sequentially renumbering them
# - You need vlan package, via "sudo apt-get install vlan"
# - You also need DHCP server and client, packages udhcpd and udhcpc 
# - You need OpenVSwitch > 2.1.  Version 2.0.2, the one that comes in Ubuntu 14.04, has a 
#   bug which sends a truncated packet with packet_in, but with buffer_id=-1 (meaning no buffer)
#   Since you don't have all the data, it's impossible to send out the correct data in packet_out.
#   This really affects DHCP.  

import re
import sys

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
    net = Mininet(switch=OVSSwitch, controller=ctrlr, autoStaticArp=True)
    c1 = net.addController('c1')

    # Switches in Gates G27.  Main distribution to servers and outside world, plus basement labs 
    # NOTE: it would be really nice if we can name these descriptively for Mininet instead of s1, etc.
    s_eor = net.addSwitch('s_eor', dpid = hex(1125908103288861)[2:]) # ('g27/r01/s4810a')
    s_r1 = net.addSwitch('s_r1', dpid = hex(1125908103297789)[2:]) # ('g27/r01/s4810b') - CURRENTLY UNCONNECTED
    s_r2 = net.addSwitch('s_r2', dpid = hex(1284990276223830)[2:]) # ('g27/r02/s4820a')
    s_r3 = net.addSwitch('s_r3', dpid = hex(1284990276223836)[2:]) # ('g27/r03/s4820a')
    s_r4 = net.addSwitch('s_r4', dpid = hex(1284990276224367)[2:]) # ('g27/r04/s4820a')
    s_r5 = net.addSwitch('s_r5', dpid = hex(1284990276224415)[2:]) # ('g27/r05/s4820a')
    s_r6 = net.addSwitch('s_r6', dpid = hex(1284990276223782)[2:]) # ('g27/r06/s4820a')
    s_r7 = net.addSwitch('s_r7', dpid = hex(1284990276224424)[2:]) # ('g27/r07/s4820a')
    s_r8 = net.addSwitch('s_r8', dpid = hex(1284990276224331)[2:]) # ('g27/r08/s4820a')
    s_r9 = net.addSwitch('s_r9', dpid = hex(1284990276224418)[2:]) # ('g27/r09/s4820a')
    s_r10 = net.addSwitch('s_r10', dpid = hex(1284990276224328)[2:]) # ('g27/r10/s4820a')
    s_r11 = net.addSwitch('s_r11', dpid = hex(1284990276268919)[2:]) # ('g27/r11/s4820a') - CURRENTLY UNCONNECTED
    s_r12 = net.addSwitch('s_r12', dpid = hex(1284990276224409)[2:]) # ('g27/r12/s4820a')
    s_r13 = net.addSwitch('s_r13', dpid = hex(1284990276224322)[2:]) # ('g27/r13/s4820a')
    s_r14 = net.addSwitch('s_r14', dpid = hex(1284990276224385)[2:]) # ('g27/r14/s4820a')
    s_r15 = net.addSwitch('s_r15', dpid = hex(1284990276224421)[2:]) # ('g27/r15/s4820a')
    # switches in r16 and r17 are not used.  
    s_r18 = net.addSwitch('s_r18', dpid = hex(1284990276224325)[2:]) # ('g27/r18/s4820a') - CURRENTLY UNCONNECTED

    # Distribution to wall jacks on floors 1-4
    s_bdf = net.addSwitch('s_bdf', dpid = hex(1125908108270984)[2:]) # ('g126/r02/s4810a')
    s_f1 = net.addSwitch('s_f1', dpid = hex(1125908103260016)[2:]) # ('g126/r02/s4810b')
    s_f2 = net.addSwitch('s_f2', dpid = hex(1125908103297849)[2:]) # ('g234/r02/s4810a')
    s_f3a = net.addSwitch('s_f3a', dpid = hex(1125908103297804)[2:]) # ('g348/r02/s4810a')
    s_f3b = net.addSwitch('s_f3b', dpid = hex(1125908103297660)[2:]) # ('g302b/r02/s4810a')
    s_f4 = net.addSwitch('s_f4', dpid = hex(1125908103297765)[2:]) # ('g448a/r02/s4810a')

    # SysLab
    s_lab_eor = net.addSwitch('s_lab_eor', dpid = hex(1125908103289164)[2:]) # ('g444/r05/s4810a') - A/K/A s_syslab_5a
    s_lab_r0 = net.addSwitch('s_lab_r0', dpid = hex(1284990276223803)[2:]) # ('g444/r00/s4820a')
    s_lab_r3 = net.addSwitch('s_lab_r3', dpid = hex(1284990276224316)[2:]) # ('g444/r03/s4820a') - MISLABELLED on spreadsheet
    s_lab_r99 = net.addSwitch('s_lab_r99', dpid = hex(1284990276223788)[2:]) # ('g444/r99/s4820a') - ALSO mislabelled
    s_lab_r5 = net.addSwitch('s_lab_r5', dpid = hex(1284990276220716)[2:]) # ('g444/r05/s4820a') - A/K/A s_lab_5b
    s_lab_r6 = net.addSwitch('s_lab_r6', dpid = hex(1284990276223779)[2:]) # ('g444/r06/s4820a')
    s_lab_r7 = net.addSwitch('s_lab_r7', dpid = hex(1284990276223785)[2:]) # ('g444/r07/s4820a')

    # TP-Link running Openflow, I think
    s_tplink = net.addSwitch('s_tplink', dpid = "1") # ('g999/r99/s4820a')

    # Links between switches.  
    # Basement switches are wired in a star topology
    # s_r1 is not connected
    net.addLink(s_eor, s_r2, 3, 49 )
    net.addLink(s_eor, s_r3, 5, 49 )
    net.addLink(s_eor, s_r4, 7, 49 )
    net.addLink(s_eor, s_r5, 9, 49 )
    net.addLink(s_eor, s_r6, 11, 49 )
    net.addLink(s_eor, s_r7, 13, 49 )
    net.addLink(s_eor, s_r8, 15, 49 )
    net.addLink(s_eor, s_r9, 17, 49 )
    net.addLink(s_eor, s_r10, 19, 49 )
    # s_r11 is not connected
    net.addLink(s_eor, s_r12, 23, 49 )
    net.addLink(s_eor, s_r13, 25, 49 )
    net.addLink(s_eor, s_r14, 27, 49 )
    net.addLink(s_eor, s_r15, 29, 49 )

    # Floor switches are wired in a star as well
    net.addLink(s_bdf, s_f1, 9, 47 )
    net.addLink(s_bdf, s_f2, 17, 47 )
    net.addLink(s_bdf, s_f3a, 23, 47 )
    net.addLink(s_bdf, s_f3b, 31, 47 )
    net.addLink(s_bdf, s_f4, 37, 47 )

    # And SysLab switches
    net.addLink(s_lab_eor, s_lab_r0, 9, 49 )
    net.addLink(s_lab_eor, s_lab_r3, 21, 49 )
    net.addLink(s_lab_eor, s_lab_r99, 19, 49 )
    net.addLink(s_lab_eor, s_lab_r5, 41, 49 )
    net.addLink(s_lab_eor, s_lab_r6, 29, 49 )
    net.addLink(s_lab_eor, s_lab_r7, 31, 49 )

    # Links between stars
    net.addLink(s_eor, s_bdf, 47, 47 )
    net.addLink(s_bdf, s_lab_eor, 45, 47 )
 
    # An odd duck
    net.addLink(s_lab_r0, s_tplink, 34, 1 )

    # Only one host and an Internet Router disguised as a host for now (because it's not part of the OF network)
    h0 = net.addHost('h0', cls=VLANHost, mac='00:00:01:00:00:10', ip='128.253.154.0', vlan=1356)
    net.addLink(s_bdf, h0, 49, 0)

    # To test DHCP functionality, ucnomment this line and comment out the fixed IP line.  Then when mininet
    # starts you issue:
    #   mininet> h1 dhclient -v -d -1 h1-eth0.1356
    # and make sure it gets its IP by going through all protocol steps.
    # h1 = net.addHost('h1', cls=VLANHost, mac='00:00:01:00:00:11', ip='0.0.0.0', vlan=1356)
    h1 = net.addHost('h1', cls=VLANHost, mac='00:00:01:00:00:11', ip='128.253.154.100', vlan=1356)
    net.addLink(s_f3a, h1, 1, 0)

    # Client for tplink, since it's a little weird
    h2 = net.addHost('h2', cls=VLANHost, mac='00:00:01:00:00:12', ip='128.253.154.101', vlan=1356)
    net.addLink(s_tplink, h2, 2, 0)

    ###### Start of static Mininet epilogue ######
    # Set up logging etc.
    lg.setLogLevel('info')
    lg.setLogLevel('output')

    # Start the network
    net.start()
    # Start the DHCP server on Internet Router.  This will actually be a DHCP proxy in the real setup.  
    startDHCPserver( h0, gw='128.253.154.0', dns='8.8.8.8')


    # Enter CLI mode
    output("Network ready\n")
    output("Press Ctrl-d or type exit to quit\n")
    CLI(net)
    net.stop()

start()