# Model of Gates Network for Mininet
# Craig Riecke, CoSciN Developer/Analyst, June, 2015
#
# To make this work:
# - You need to be at Mininet > 2.2, which you should build from source if on Ubuntu 14.04 (the
#   latest dpkg is Mininet 2.1).  This will make the links use the right ports instead of 
#   sequentially renumbering them
# - You need vlan package, via "sudo apt-get install vlan"

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


def start(ip="127.0.0.1",port=6633):

    ctrlr = lambda n: RemoteController(n, ip=ip, port=port, inNamespace=False)
    net = Mininet(switch=OVSSwitch, controller=ctrlr, autoStaticArp=False)
    c1 = net.addController('c1')

    # Switches in Gates G27.  Main distribution to servers and outside world, plus basement labs 
    # NOTE: it would be really nice if we can name these descriptively for Mininet instead of s1, etc.
    s_eor = net.addSwitch('s1') # ('g27/r01/s4810a')
    s_r1 = net.addSwitch('s2') # ('g27/r01/s4810b')
    s_r2 = net.addSwitch('s3') # ('g27/r02/s4820a')
    s_r3 = net.addSwitch('s4') # ('g27/r03/s4820a')
    s_r4 = net.addSwitch('s5') # ('g27/r04/s4820a')
    s_r5 = net.addSwitch('s6') # ('g27/r05/s4820a')
    s_r6 = net.addSwitch('s7') # ('g27/r06/s4820a')
    s_r7 = net.addSwitch('s8') # ('g27/r07/s4820a')
    s_r8 = net.addSwitch('s9') # ('g27/r08/s4820a')
    s_r9 = net.addSwitch('s10') # ('g27/r09/s4820a')
    s_r10 = net.addSwitch('s11') # ('g27/r10/s4820a')
    s_r11 = net.addSwitch('s12') # ('g27/r11/s4820a')
    s_r12 = net.addSwitch('s13') # ('g27/r12/s4820a')
    s_r13 = net.addSwitch('s14') # ('g27/r13/s4820a')
    s_r14 = net.addSwitch('s15') # ('g27/r14/s4820a')
    s_r15 = net.addSwitch('s16') # ('g27/r15/s4820a')
    # switches in r16 and r17 are not used.  s_r18 is currently orphaned on the network (no links)
    s_r18 = net.addSwitch('s17') # ('g27/r18/s4820a')

    # Distribution to wall jacks on floors 1-4
    s_bdf = net.addSwitch('s18') # ('g126/r02/s4810a')
    s_f1 = net.addSwitch('s19') # ('g126/r02/s4810b')
    s_f2 = net.addSwitch('s20') # ('g234/r02/s4810a')
    s_f3a = net.addSwitch('s21') # ('g348/r02/s4810a')
    s_f3b = net.addSwitch('s22') # ('g302b/r02/s4810a')
    s_f4 = net.addSwitch('s23') # ('g448a/r02/s4810a')

    # SysLab
    s_syslab_eor = net.addSwitch('s24') # ('g444/r00/s4820a')
    s_syslab_r3 = net.addSwitch('s25') # ('g444/r03/s4820a')
    s_syslab_r5a = net.addSwitch('s26') # ('g444/r05/s4810a')
    s_syslab_r5b = net.addSwitch('s27') # ('g444/r05/s4820a')
    s_syslab_r6 = net.addSwitch('s28') # ('g444/r06/s4820a')
    s_syslab_r7 = net.addSwitch('s29') # ('g444/r07/s4820a')
    s_syslab_out = net.addSwitch('s30') # ('g999/r99/s4820a')

    # TP-Link running Openflow, I think
    s_softswitch = net.addSwitch('s31')# ('g999/r99/s4820a')

    # Links between switches.  
    # Basement switches are wired in a star topology
    net.addLink(s_eor, s_r2, 3, 49 )
    net.addLink(s_eor, s_r3, 5, 49 )
    net.addLink(s_eor, s_r4, 7, 49 )
    net.addLink(s_eor, s_r5, 9, 49 )
    net.addLink(s_eor, s_r6, 11, 49 )
    net.addLink(s_eor, s_r7, 13, 49 )
    net.addLink(s_eor, s_r8, 15, 49 )
    net.addLink(s_eor, s_r9, 17, 49 )
    net.addLink(s_eor, s_r10, 19, 49 )
    net.addLink(s_eor, s_r11, 21, 49 )
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
    net.addLink(s_syslab_eor, s_syslab_r3, 21, 49 )
    net.addLink(s_syslab_eor, s_syslab_r5a, 19, 49 )
    net.addLink(s_syslab_eor, s_syslab_r5b, 41, 49 )
    net.addLink(s_syslab_eor, s_syslab_r6, 29, 49 )
    net.addLink(s_syslab_eor, s_syslab_r7, 31, 49 )
    net.addLink(s_syslab_eor, s_syslab_out, 9, 49 )

    # Links between stars
    net.addLink(s_eor, s_bdf, 47, 47 )
    net.addLink(s_bdf, s_syslab_eor, 45, 47 )
 
    # An odd duck
    net.addLink(s_syslab_out, s_softswitch, 34, 1 )

    # Only one host and an Internet Router disguised as a host for now (because it's not part of the OF network)
    h0 = net.addHost('h0', cls=VLANHost, mac='00:00:01:00:00:10', ip='128.253.154.0', vlan=1356)
    h1 = net.addHost('h1', cls=VLANHost, mac='00:00:01:00:00:11', ip='128.253.154.100', vlan=1356)
    # h0 = net.addHost('h0', mac='00:00:01:00:00:10', ip='128.253.154.0', vlan=1356)
    # h1 = net.addHost('h1', mac='00:00:01:00:00:11', ip='128.253.154.100', vlan=1356)
    net.addLink(s_bdf, h0, 49, 0)
    net.addLink(s_f3a, h1, 1, 0)

    ###### Start of static Mininet epilogue ######
    # Set up logging etc.
    lg.setLogLevel('info')
    lg.setLogLevel('output')

    # Start the network and prime other ARP caches
    net.start()

    # Enter CLI mode
    output("Network ready\n")
    output("Press Ctrl-d or type exit to quit\n")
    CLI(net)
    net.stop()

start()