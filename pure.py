'''
Try to implement routing in pure OpenFlow environment

'''

DEBUG = True
CONFIG_FILE = './ext/pure.config'
HOST = 'localhost'
PORT = 9000

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

import socket, threading, asyncore


class ControlHandler(asyncore.dispatcher_with_send):
	PROMPT = '> '

	def handle_read(self):
		cmd = self.recv(1024)
		cmd = cmd.split()
		if not cmd:
			reply = self.PROMPT
			self.send(reply)
			return
		reply = None
		if cmd[0] == 'show':
			reply = self._show(cmd[1:])
		elif cmd[0] == 'set':
			reply = self._set(cmd[1:])
		elif cmd[0] == 'del':
			reply = self._delete(cmd[1:])
		elif cmd[0] == 'help' or cmd[0] == '?':
			reply = self._help()
		elif cmd[0] == 'exit' or cmd[0] == 'quit':
			self.close()
			return
		else:
			reply = 'Unknown command. Try "help" for help.'
		reply = reply + '\n' + self.PROMPT
		self.send(reply)

	def _help(self):
		helpInfo = '''
Supported commands:

show                show all switches and their state
show <switch name>  show a switch's detailed information
show route          show routing information
set <switch name> <port number> <ip addresses> <network> <cost>
                    set a route entry as in the config file
del <switch name> <port number>
                    delete a route entry
exit/quit           exit
help/?              show this message'''
		return helpInfo

	def _delete(self, cmd):
		try:
			switchName = cmd[0]
			portNumber = int(cmd[1])
		except:
			return 'Something wrong with your parameters'

		for entry in routingEntity.routingTable:
			if entry.name == switchName and \
					entry.port == portNumber:
				routingEntity.routingTable.remove(entry)
				routingEntity.infoCondition == Routing.ROUTE_DIRTY
				switch = routingEntity._getSwitchByName(switchName)
				port = switch.getPort(portNumber)
				port.mode = Port.SWITCH_MODE
				switch._update_mode()
				return 'Entry removed successfully'
		return 'No such entry\n'

	def _set(self, cmd):
		try:
			switchName = cmd[0]
			portNumber = int(cmd[1])
			ip = IPAddr(cmd[2])
			network = cmd[3]
			cost = int(cmd[4])
		except:
			return 'Something wrong with your parameters'

		targetEntry = None
		for entry in routingEntity.routingTable:
			if entry.name == switchName and \
					entry.port == portNumber:
				targetEntry = entry
				break

		if targetEntry:
			targetEntry.portIpAddress = ip
			targetEntry.network = network
			targetEntry.cost = cost
		else:
			switch = routingEntity._getSwitchByName(switchName)
			if not switch:
				return 'No such switch'
			port = switch.getPort(portNumber)
			port.mode = Port.ROUTER_MODE
			port.ip = ip
			port.network = network
			port.cost = cost
			switch._update_mode()
			new = RoutingTableEntry(switchName, portNumber, ip, network, cost)
			routingEntity.routingTable.add(new)
			routingEntity.costToNetwork[switchName, network] = cost
		routingEntity.infoCondition == Routing.ROUTE_DIRTY
		return 'Route entry set successful'


	def _show_switches(self):
		# header of table:
		reply = '{0:15} {1:20} {2:10} {3:5}'.format('Switch Name',
				'Datapath ID', 'Mode', 'Ports') + '\n'
		for dpid in switchOfDpid:
			switch = switchOfDpid[dpid]
			name = switch.name
			dpid_str = dpidToStr(switch.dpid)
			stringOfMode = {
					1:'switch',
					2:'router',
					3:'hybrid'}
			mode = stringOfMode[switch.mode]
			ports = len(switch.ports)
			line = '{0:15} {1:20} {2:10} {3:5}'.format(name,
					dpid_str, mode, ports) + '\n'
			reply += line
		return reply

	def _show_route(self):
		stringOfConfition = {
				0:'CLEAN',
				1:'DIRTY'}
		reply = 'Routing infomation is ' + \
				stringOfConfition[routingEntity.infoCondition] + '\n'
		# header of table:
		reply += '{0:10} {1:5} {2:20} {3:20} {4:5}'.format('Switch',
				'Port', 'IP', 'Network / Mask', 'Cost') + '\n'
		for entry in routingEntity.routingTable:
			switch = entry.name
			port = entry.port
			ip = entry.portIpAddress
			network = entry.network
			cost = entry.cost
			line = '{0:10} {1:5} {2:20} {3:20} {4:5}'.format(switch,
					port, ip, network, cost) + '\n'
			reply += line
		return reply

	def _show_switch_detail(self, cmd):
		switchName = cmd[0]
		reply = ''
		switch = None
		for dpid in switchOfDpid:
			if switchOfDpid[dpid].name == switchName:
				switch = switchOfDpid[dpid]
				break
		if switch == None:
			reply = 'No switch named with: ' + switchName
			return reply
		
		reply += 'Showing switch ' + switchName + ':\n'
		reply += 'Ports:\n'
		portHeader = '{0:10} {1:10} {2:20} {3:10} {4:20} {5:20}'.format(
				'Name', 'Num.', 'MAC', 'Mode', 'IP', 'Adjacency') + '\n'
		reply += portHeader
		for port in switch.ports:
			name = port.name
			number = port.number
			mac = port.mac
			stringOfMode = {
					1:'switch',
					2:'router'}
			mode = stringOfMode[port.mode]
			if port.ip:
				ip = port.ip
			else:
				ip = 'N/A'
			if port.adjacency:
				adjacency = port.adjacency.name
			elif port.network:
				adjacency = port.network
			else:
				adjacency = 'N/A'

			line = '{0:10} {1:10} {2:20} {3:10} {4:20} {5:20}'.format(
					name, number, mac, mode, ip, adjacency) + '\n'
			reply += line
		reply += 'Next hop:\n'
		nextHopHeader = '{0:15} {1:15}'.format('Destination', 'Next hop') \
						+ '\n'
		reply += nextHopHeader
		for s in switch.nextHop:
			line = '{0:15} {1:15}'.format(s.name, switch.nextHop[s].name) \
					+ '\n'
			reply += line
		return reply

	def _show(self, cmd):
		reply = None
		if cmd == []:
			reply = self._show_switches()
		elif cmd[0] == 'route':
			reply = self._show_route()
		else:
			reply = self._show_switch_detail(cmd)
		return reply



controllInterfaceServer = None

class ControlInterfaceServer(asyncore.dispatcher):
	def	 __init__(self):
		asyncore.dispatcher.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind( (HOST, PORT) )
		self.listen(1)

	def handle_accept(self):
		pair = self.accept()
		if pair is not None:
			socket, address = pair
			print 'Incoming connection from ', address
			handler = ControlHandler(socket)
			socket.send('welcome!\n' + ControlHandler.PROMPT)

# datapath id -> switch instance
# example: switchOfDpid[dpid] = switch instance
switchOfDpid = {}

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
	# TODO: add a PPP mode for links between routers

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

		destIp = ipPacket.dstip
		destSwitch = routingEntity.findSwitchOfDest(self, destIp)

		if destSwitch == None:
			# no route to the dest network
			# TODO should send an ICMP but drop it by now
			self._drop(event)
		elif destSwitch == self:
			outPort = routingEntity.getOutPortForIp(self, destIp)
			self.installLastHop(event, destIp, outPort)
		else:
			nextHopSwitch = self.nextHop[destSwitch]
			outPort, peerPort = self.adjacency[nextHopSwitch]
			peerMac = routingEntity._getMacOfPort(nextHopSwitch, peerPort)
			self.installRouteEntry(destIp, outPort, peerMac)
			self._router_output(event, outPort, peerMac)

			if DEBUG:
				print '*** Next Hop:'
				print self, nextHopSwitch
				print outPort, peerPort



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
		self.server = ControlInterfaceServer()
		self.server_thread = threading.Thread(target = asyncore.loop)
		self.server_thread.daemon = True
		self.server_thread.start()

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
