'''
Try to implement routing in pure OpenFlow environment

'''

DEBUG = True
CONFIG_FILE = './ext/pure.config'

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST

log = core.getLogger()

from pox.lib.addresses import IPAddr, EthAddr

# datapath id -> switch instance
# example: switchOfDpid[dpid] = switch instance
switchOfDpid = {}

class Host(object):
	def __init__(self, mac, ip):
		if isinstance(mac, EthAddr):
			self.mac = mac
		else:
			raise TypeError("MAC address must be of type EthAddr")
		if isinstance(ip, IPAddr):
			self.ip = ip
		else:
			raise TypeError("IP address must be of type IPAddr")

	def __eq__(self, other):
		if self == other:
			return True
		else:
			return False

# host -> dpid + port (position of host)
# example: positionOfHost[Host instance] = (dpid, port)
positionOfHost = {}

# mac address -> host
# example: hostOfMac[EthAddr instance] = Host instance
hostOfMac = {}

# ip address -> host
# example: hostOfIP[IPAddr instance] = Host instance
hostOfIP = {}

class RoutingTableEntry(object):
	def __init__(self, switchName, portNumber, ipAddress, \
						network, cost):
		self.name = switchName
		self.port = portNumber
		self.portIpAddress = ipAddress
		self.network = network
		self.cost = cost

	def __eq__(self, other):
		if self.name == other.name and \
			self.port == other.port and \
			self.portIpAddress == other.portIpAddress and \
			self.network == other.network and \
			self.cost == other.cost:
			return True
		else:
			return False

routingEntity = None

class Routing(object):

	# routing information
	ROUTE_CLEAN = 0
	ROUTE_DIRTY = 1

	def __init__(self):
		# read in routing table from config file
		self.costToNetwork = {}		# cost of switch to network
					# example: costToNetwork[switch name, network] = cost
		self.routingTable = set()
		config = file(CONFIG_FILE)
		for line in config:
			line = line.split()
			if '#' in line or line == []:
				continue
			new = RoutingTableEntry(line[0],	# switchName
					int(line[1]),				# portNumber
					IPAddr(line[2]),			# ipAddress
					line[3],					# network
					int(line[4]))				# cost
			self.routingTable.add(new)
			self.costToNetwork[line[0],line[3]] = int(line[4])
		# data structure used in routing calculation
		self.cost = {}	# cost of any pair
						# example:	cost[switch A, switch B] = 10
		self.infoCondition = self.ROUTE_DIRTY
		

	def findSwitchNameAndNetworkOfDest(self, destIp):
		dest = IPAddr(destIp)
		ans = []
		for entry in self.routingTable:
			if dest.inNetwork(entry.network):
				ans.append( (entry.name, entry.network) )
		return ans

	def _getSwitchByName(self, name):
		for dpid in switchOfDpid:
			if switchOfDpid[dpid].name == name:
				return switchOfDpid[dpid]
		return None

	def findSwitchOfDest(self, srcSwitch, destIp):
		# find switch(maybe many) connected to the dest network
		temp = []
		nameAndNet = self.findSwitchNameAndNetworkOfDest(destIp)
	
		for dpid in switchOfDpid:
			for name,network in nameAndNet:
				if switchOfDpid[dpid].name == name:
					temp.append( (switchOfDpid[dpid], network))
	
		# find the nearest one from srcSwitch
		# if no route or routes infoCondition is ROUTE_DIRTY, return None
		if temp == []:
			return None
		nearest = None # (switch, network)
		for switch, network in temp:
			try:
				c = self.cost[srcSwitch, switch] + \
					self.costToNetwork[switch.name, network]
				if nearest == None or \
						c < self.cost[srcSwitch, nearest] + \
							self.costToNetwork[nearest[0].name, nearest[1]]:
					nearest = (switch, network)
			except KeyError:
				if self.infoCondition == self.ROUTE_DIRTY:
					return None
				else:
					continue

		if nearest:
			return nearest[0]
		else:
			return None

	def getRoute(self, srcSwitch, destSwitch):
		path = []
		if srcSwitch == destSwitch:
			return path

		now = srcSwitch.nextHop[destSwitch]
		while now != destSwitch:
			path.append(now)
			now = now.nextHop[destSwitch]
		return path

	
	def _are_adjacency(self, u, v):
		# u and v are two switches
		for port in u.ports:
			if port.adjacency and port.adjacency.dpid == v.dpid:
				# port.adjacency maybe None
				return True
		return False

	def calculate(self):
		# floyd-warshall algorithm
		# init data structures
		self.cost = {}
		allSwitches = []
		for dpid in switchOfDpid:
			switch = switchOfDpid[dpid]
			switch.nextHop = {}
			allSwitches.append(switch)
			for port in switch.ports:
				if port.adjacency != None:
					self.cost[switch, port.adjacency] = port.cost
					switch.nextHop[port.adjacency] = port.adjacency
#		if DEBUG:
#			print '*** Cost array before calculate:'
#			print self.cost
#			print 'nextHop:'
#			for s in allSwitches:
#				print s, s.nextHop

		# the O(v^3) main loop		
		for t in allSwitches:
			for u in allSwitches:
				for v in allSwitches:
					try:
						newCost = self.cost[u,t] + self.cost[t,v]
						if ((u,v) not in self.cost) or \
								newCost < self.cost[u,v]:
							self.cost[u,v] = newCost
							if self._are_adjacency(u, v):
								u.nextHop[v] = v
							elif u == v:
								continue
							else:
								u.nextHop[v] = u.nextHop[t]
					except KeyError:
						continue

		self.infoCondition = self.ROUTE_CLEAN
		if DEBUG:
			print '*** Cost array:'
			print self.cost
			print 'allSwitches:'
			print allSwitches
			print 'nextHop:'
			for s in allSwitches:
				print s, s.nextHop

	def getOutPortForIp(self, switch, destIp):
		if DEBUG:
			print '*** _getOutPortForIp:'
			print switch, destIp
		dest = IPAddr(destIp)
		for entry in self.routingTable:
			if dest.inNetwork(entry.network) and \
						switch.name == entry.name:
				return entry.port	# port number
		return None

	def _getMacOfPort(self, switch, portNumber):
		for port in switch.ports:
			if port.number == portNumber:
				return port.mac

	def	installRoute(self, event, srcSwitch, destSwitch, path, destIp):
		destSwitch.installLastHop(event, destIp, 
						self.getOutPortForIp(destSwitch, destIp))
		if srcSwitch == destSwitch:
			return


		fullPath = []
		fullPath.append(srcSwitch)
		fullPath.extend(path)
		if DEBUG:
			print '*** fullPath of ', srcSwitch, destSwitch
			print fullPath

		# install flow in reverse order to avoid another 
		# PacketIn event
		fullPath.reverse()
		
		for i in range(0, len(fullPath)):
			curr = fullPath[i]
			if i == 0:
				curr.installRouteEntry(destIp, curr.adjacency[destSwitch][0],
				self._getMacOfPort(destSwitch, curr.adjacency[destSwitch][1]))
			else:
				nextHop = fullPath[i - 1]
				curr.installRouteEntry(destIp, curr.adjacency[nextHop][0],
					self._getMacOfPort(nextHop, curr.adjacency[nextHop][1]))
	



class Port(EventMixin):

	SWITCH_MODE = 1
	ROUTER_MODE = 2

	def __init__(self, switch, port):
		self.name = port.name
		self.number = port.port_no
		self.mac = port.hw_addr
		self.state = port.state	
		self.switch = switch	# which switch this port belongs to
		self.mode = self.SWITCH_MODE
	
		# for routing only
		self.ip = None
		self.network = None
		self.adjacency = None
		self.cost = self._calcCost(port.curr)

	def _calcCost(self, curr):
		# port.curr is a number of 12 bits,
		# defined in openflow.libopenflow_01.py: 
		# ofp_port_features_rev_map & ofp_phy_port
		curr = curr & 0x7f	# get last 7 bits
		return 64/curr


class Switch(EventMixin):

	# defined in openflow specificaiton
	LOCAL_PORT = 0xfffe

	SWITCH_MODE = 1 # when all ports in SWITCH_MODE
	ROUTER_MODE = 2 # when all ports in ROUTER_MODE
	HYBRID_MODE = 3	# the switch is in hybrid mode when some ports are
					# in SWITCH_MODE, while others in ROUTER_MODE

	# in seconds
	ARP_TIMEOUT = 60
	ROUTE_TIMEOUT = 100
	HARD_TIMEOUT = 600

	# routing information
	ROUTE_CLEAN = 0
	ROUTE_DIRTY = 1

	# datalink type, see http://en.wikipedia.org/wiki/EtherType
	DL_IP4 = 0x0800
	DL_ARP = 0x0806
	DL_IP6 = 0x86dd

	def __init__(self, dpid, connection):
		self.dpid = dpid
		self.connection = connection
		self.name = None	# name of the switch, like "s1"
		self.ports = self._init_ports(connection.features.ports)
		self._config_ports()
		self.mode = self.SWITCH_MODE
		self._update_mode()
		self.listeners = self.listenTo(connection)
		# for routing
		self.nextHop = {} # nextHop[destination switch] = next hop switch
		self.infoCondition = self.ROUTE_DIRTY

		self.arp = {}	# IPAddr -> EthAddr
						# example: arp[IPAddr] = EthAddr
		self.portOfMac = {}	# dest EthAddr -> output port
							# example: portOfMac[EthAddr] = port
		self.adjacency = {}	# peerSwitch -> local port, peerSwitchPort
						# example: adjacency[switch] = (local Port number,
						#						peer switch port number)
		self.queue = []	# a buffer, saves packet we don't know how
						# to forward now
						# example: queue.append(event)
		if DEBUG:
			for port in self.ports:
				print port.name, port.number, port.mac, port.ip, port.network, port.mode

	def _init_ports(self, ports):
		portList = []
		for	port in ports:
			if port.port_no == self.LOCAL_PORT:
				self.name = port.name
			else:
				portList.append( Port(self, port))
		return portList

	def _install_flow_forward_to_controller(self, ipAddress):
		'''
			install a flow entry that forwards packet to controller for certain 
			destination-ip-address
		'''
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match(dl_type = self.DL_IP4,
								 nw_dst = ipAddress)
		msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		self.connection.send(msg)
		

	def _config_ports(self):
		config = file(CONFIG_FILE)
		for line in config:
			line = line.split()
			# then line[0] through line[3] are:
			# switch name, port, ip, network connected to port
			if '#' in line or line == []:
				continue
			if line[0] == self.name:
				port = self.getPort(line[1])
				if port:
					port.ip = IPAddr(line[2])
					port.network = line[3]
					port.mode = Port.ROUTER_MODE
					self._install_flow_forward_to_controller(port.ip)
				else:
					log.warning('switch %s has no port %s, check the config file' % 
																(line[0], line[1]))

	def _update_mode(self):
		routerMode = 0
		switchMode = 0
		for port in self.ports:
			if port.mode == Port.SWITCH_MODE:
				switchMode += 1
			if port.mode == Port.ROUTER_MODE:
				routerMode += 1

		if routerMode == 0:
			self.mode = self.SWITCH_MODE
			return
		if switchMode == 0:
			self.mode = self.ROUTER_MODE
			return
		self.mode = self.HYBRID_MODE

	def getPort(self, portNumber):
		for	port in self.ports:
			if int(port.number) == int(portNumber):
				return port
		return None

	def addAdjacency(self, localPortNumber, 
					remoteSwitchDpid, remotePortNumber):
		port = self.getPort(localPortNumber)
		port.adjacency = switchOfDpid[remoteSwitchDpid]
		self.adjacency[switchOfDpid[remoteSwitchDpid]] = \
								(localPortNumber, remotePortNumber)
		routingEntity.infoCondition = Routing.ROUTE_DIRTY

	def removeAdjacency(self, localPortNumber, remoteSwitchDpid):
		port = self.getPort(localPortNumber)
		port.adjacency = None
		try:
			del self.adjacency[switchOfDpid[remoteSwitchDpid]]
			print '*** adjacency removed:', switchOfDpid[remoteSwitchDpid]
		except KeyError:
			pass
		routingEntity.infoCondition = Routing.ROUTE_DIRTY

	def _flood_switchModePort(self, event):
		msg = of.ofp_packet_out()
		msg.data = event.ofp
		msg.in_port = event.port
		if self.mode == self.SWITCH_MODE:
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		else:
			for p in self.ports:
				if p.mode == Port.SWITCH_MODE and (not int(p.number) == int(event.port)):
					msg.actions.append(of.ofp_action_output(port = p.number))
				# this implies that if ingress port is the only SWITCH_MODE port,
				# the packet will be dropped
		self.connection.send(msg)

	def _drop(self, event, install_flow_entry = False):
		packet = event.parsed
		if install_flow_entry:
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match(in_port = event.port,
									 dl_dst = packet.dst)
			msg.idle_timeout = self.ARP_TIMEOUT
			msg.hard_timeout = self.HARD_TIMEOUT
			msg.buffer_id = event.ofp.buffer_id
		else:
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port

		self.connection.send(msg)

	def _output_toPort(self, event, outport, install_flow_entry = True):
		packet = event.parsed
		if install_flow_entry:
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match(in_port = event.port,
									 dl_dst = packet.dst)
			msg.idle_timeout = self.ARP_TIMEOUT
			msg.hard_timeout = self.HARD_TIMEOUT
		else:
			msg = of.ofp_packet_out()

		msg.actions.append(of.ofp_action_output(port = outport))
		msg.data = event.ofp
		msg.in_port = event.port
		self.connection.send(msg)

	def _switch_packetIn_handler(self, event):
		'''
			_switch_packetIn_handler handles SWITCH_MODE port's packetIn messages
		'''
		packet = event.parsed
		self.portOfMac[packet.src] = event.port
		if packet.dst.is_multicast or (packet.dst not in self.portOfMac):
			self._flood_switchModePort(event)
			return
		else:
			outport = self.portOfMac[packet.dst]
			if outport == event.port:
				self._drop(event)
			else:
				self._output_toPort(event, outport)

	def	 _tryPurgeQueue(self):
		for i in range(0, len(self.queue)):
			packet = self.queue[i].parsed
			ipPacket = packet.next
			destIp = IPAddr(ipPacket.dstip)
			peerMac = self.arp[destIp]
			outPort = routingEntity.getOutPortForIp(self, destIp)
			self._router_output(self.queue[i], outPort, peerMac)
			del self.queue[i]
										

	def _router_handle_arp(self, event):
		arpPacket = event.parsed.next
		ingressPort = self.getPort(event.port)
		if arpPacket.opcode == arp.REQUEST and \
				arpPacket.protodst == ingressPort.ip:
			r = arp()
			r.opcode = arp.REPLY
			r.hwdst = arpPacket.hwsrc
			r.hwsrc = ingressPort.mac
			r.protodst = arpPacket.protosrc
			r.protosrc = arpPacket.protodst
			e = ethernet(type = ethernet.ARP_TYPE,
						 src = ingressPort.mac, 
						 dst = arpPacket.hwsrc)
			e.set_payload(r)
			msg = of.ofp_packet_out()
			msg.data = e.pack()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.in_port = event.port
			event.connection.send(msg)
		elif arpPacket.opcode == arp.REPLY:
			ip = IPAddr(arpPacket.protosrc)
			mac = EthAddr(arpPacket.hwsrc)
			self.arp[ip] = EthAddr(mac)
			self._tryPurgeQueue()
			self.installRouteEntry(ip, event.port, mac)
		else:
			self._drop(event)

	def _router_handle_icmp(self, event):
		packet = event.parsed
		ipPacket = packet.next
		icmpPacket = ipPacket.next
		replied = False
		if icmpPacket.type == TYPE_ECHO_REQUEST:
			for port in self.ports:
				if port.ip == ipPacket.dstip:
					# ping reply
					reply = icmp()
					reply.type = TYPE_ECHO_REPLY
					reply.payload = icmpPacket.payload # seq, id, etc.
					# ip packet
					i = ipv4()
					i.protocol = i.ICMP_PROTOCOL
					i.srcip = ipPacket.dstip
					i.dstip = ipPacket.srcip
					i.payload = reply
					# ethernet
					e = ethernet(type = ethernet.IP_TYPE,
								 src = packet.dst,
								 dst = packet.src)
					e.payload = i
					# openflow msg
					msg = of.ofp_packet_out()
					msg.actions.append(of.ofp_action_output(
										port = of.OFPP_IN_PORT))
					msg.data = e.pack()
					msg.in_port = event.port
					self.connection.send(msg)
					# break the for-loop
					replied = True
					break
		if not replied:
			# this must be other's ping
			self._router_handle_ipv4(event)

	def installRouteEntry(self, destIp, outPort, peerMac):
		msg = of.ofp_flow_mod(command = of.OFPFC_MODIFY,
				idle_timeout = self.ROUTE_TIMEOUT,
				hard_timeout = self.HARD_TIMEOUT)
		msg.match = of.ofp_match(dl_type = self.DL_IP4,
								nw_dst = destIp)
		msg.actions.append(of.ofp_action_dl_addr.set_src(
											self.getPort(outPort).mac))
		msg.actions.append(of.ofp_action_dl_addr.set_dst(peerMac))
		msg.actions.append(of.ofp_action_output(port = outPort))
		self.connection.send(msg)
	
	def _sendArpReq(self, destIp, outPort):
		r = arp()
		r.opcode = arp.REQUEST
		r.hwsrc = self.getPort(outPort).mac
		r.hwdst = ETHER_BROADCAST
		r.protodst = IPAddr(destIp)
		r.protosrc = self.getPort(outPort).ip
		e = ethernet(type = ethernet.ARP_TYPE,
					src = r.hwsrc,
					dst = r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port = outPort))
		self.connection.send(msg)

	def _router_output(self, event, outPort, peerMac):
		msg = of.ofp_packet_out()
		msg.data = event.ofp
		msg.actions.append(of.ofp_action_dl_addr.set_src(
											self.getPort(outPort).mac))
		msg.actions.append(of.ofp_action_dl_addr.set_dst(peerMac))
		msg.actions.append(of.ofp_action_output(port = outPort))
		self.connection.send(msg)

	def installLastHop(self, event, destIp, outPort):
		dest = IPAddr(destIp)
		if dest in self.arp:
			peerMac = self.arp[dest]
			self._router_output(event, outPort, peerMac)
			self.installRouteEntry(destIp, outPort, peerMac)
		else:
			self.queue.append(event)
			self._sendArpReq(destIp, outPort)

	def _router_handle_ipv4(self, event):
		packet = event.parsed
		ipPacket = packet.next
		if routingEntity.infoCondition == routingEntity.ROUTE_DIRTY:
			routingEntity.calculate()

		destSwitch = routingEntity.findSwitchOfDest(self, ipPacket.dstip)

		if destSwitch == None:
			# no route to the dest network
			# TODO should send an ICMP but drop it by now
			self._drop(event)
		else:
			path = routingEntity.getRoute(self, destSwitch)
			routingEntity.installRoute(event, self, destSwitch,
										path, ipPacket.dstip)


	def _router_packetIn_handler(self, event):
		'''
			_router_packetIn_handler handles ROUTER_MODE port's packetIn messages
		'''
		packet = event.parsed
		port = self.getPort(event.port)
		try:
			l3_packet = packet.next
		except:
			l3_packet = None

		try:
			l4_packet = l3_packet.next
		except:
			l4_packet = None

		if isinstance(l3_packet, arp):
			self._router_handle_arp(event)
		elif isinstance(l4_packet, icmp):
			self._router_handle_icmp(event)
		elif isinstance(l3_packet, ipv4):
			self._router_handle_ipv4(event)
		else:
			self._drop(event)
			log.warning('some packet dropped by the router...')

	def _handle_PacketIn(self, event):
		packet = event.parsed
		if packet.effective_ethertype == packet.LLDP_TYPE:
			# ignore LLDP(used by topology discovery)
			return
		if self.getPort(event.port) == None:
			log.error('ERROR:')		
			log.error('packet in occurs from ' + event.port)
			log.error('and all ports of the switch are: ' + self.ports)
		portMode = self.getPort(event.port).mode
		if portMode == Port.SWITCH_MODE:
			self._switch_packetIn_handler(event)
		elif portMode == Port.ROUTER_MODE:
			self._router_packetIn_handler(event)
		else:
			log.error('***** ERROR: should never be here *****')
	
	def _handle_ConnectionDown(self, event):
		if DEBUG:
			print 'switch disconnected, dpid=%s' % (self.dpid)
		del switchOfDpid[self.dpid]

	def __eq__(self, other):
		if other == None:
			return False
		if self.dpid == other.dpid:
			return True
		else:
			return False

	def __str__(self):
		return self.name

	def __repr__(self):
		return self.name


class Pure(EventMixin):

#	_eventMixin_events = set([
#								RouteUpdated,
#							])

	def __init__(self):
		self.listenTo(core.openflow, priority = 0)
		self.listenTo(core.openflow_discovery)
		global routingEntity
		routingEntity = Routing()

	def _handle_ConnectionUp(self, event):
		try:
			switchOfDpid[event.dpid]
		except KeyError:
			new = Switch(event.dpid, event.connection)
			switchOfDpid[event.dpid] = new
			if DEBUG:
				print 'new switch connected, dpid=%s' % (event.dpid)
				print switchOfDpid

	def _handle_LinkEvent(self, event):
		link = event.link
		if DEBUG:
			print link
		if event.added:
			# new link discovered
			switchOfDpid[link.dpid1].addAdjacency(link.port1, link.dpid2,
												link.port2)
			switchOfDpid[link.dpid2].addAdjacency(link.port2, link.dpid1,
												link.port1)
		elif event.removed:
			# link down
			switchOfDpid[link.dpid1].removeAdjacency(link.port1, link.dpid2)
			switchOfDpid[link.dpid2].removeAdjacency(link.port2, link.dpid1)

def launch():
	if 'openflow_discovery' not in core.components:
		import pox.openflow.discovery as discovery
		core.registerNew(discovery.Discovery)

	core.registerNew(Pure)
