
import array
import trio
import socket
import struct
import sys
import os
import uuid
import errno
from collections import namedtuple

from pyroute2 import netlink
from pyroute2.netlink import rtnl

import pytest
import asyncdbus

AF_NETLINK = 16
AF_MCTP = 45
ARPHRD_MCTP = 290
IFLA_MCTP_NET = 1

MAX_SOCKADDR_SIZE = 56

# can be serialised into a NLMSG_ERROR
class NetlinkError(Exception):
    def __init__(self, errno, msg = None):
        self.errno = errno
        self.msg = msg

    def to_nlmsg(self, seq = 0):
        resp = netlink.nlmsgerr()
        resp['header']['sequence_number'] = seq
        resp['header']['pid'] = 0
        resp['header']['type'] = netlink.NLMSG_ERROR
        resp['error'] = -self.errno
        if self.msg:
            resp['attrs'] = [['NLMSGERR_ATTR_MSG', self.msg]]
        return resp

class System:
    class Interface:
        """Interface constructor.

        Initial mtu is set to max_mtu.
        """
        def __init__(self, name, ifindex, net, lladdr, min_mtu, max_mtu, up = False):
            self.name = name
            self.ifindex = ifindex
            self.net = net
            self.lladdr = lladdr,
            self.min_mtu = min_mtu
            self.max_mtu = max_mtu
            self.mtu = max_mtu
            self.up = up

        def __str__(self):
            lladdrstr = ':'.join('%02x' % ord(b) for b in self.lladdr)
            return f"{self.name}: net {self.net} lladdr {lladdrstr}"

    class Address:
        def __init__(self, iface, eid):
            self.iface = iface
            self.eid = eid

        def __str__(self):
            return f"{self.eid} ({self.iface.name})"

    class Neighbour:
        def __init__(self, iface, lladdr, eid):
            self.iface = iface
            self.lladdr = lladdr
            self.eid = eid

        def __str__(self):
            lladdrstr = ':'.join('%02x' % b for b in self.lladdr)
            return f"{self.eid} -> {lladdrstr} {self.iface.name}"

    class Route:
        def __init__(self, iface, start_eid, extent_eid, mtu = 0):
            self.iface = iface
            self.start_eid = start_eid
            self.end_eid = start_eid + extent_eid
            self.mtu = mtu

        def __str__(self):
            return (f"{self.start_eid}-{self.end_eid} -> " +
                    f"{self.iface.name} mtu {self.mtu}")

    def __init__(self):
        self.interfaces = []
        self.addresses = []
        self.neighbours = []
        self.routes = []
        self.nl = None

    async def add_route(self, route):
        self.routes.append(route)
        if self.nl:
            await self.nl.notify_newroute(route)

    async def del_route(self, route):
        route = self.lookup_route_exact(route.iface, route.start_eid,
                route.end_eid)
        if not route:
            raise NetlinkError(errno.ENOENT)

        self.routes.remove(route)
        if self.nl:
            await self.nl.notify_delroute(route)

    async def add_interface(self, iface):
        self.interfaces.append(iface)
        if self.nl:
            await self.nl.notify_newlink(iface)

    async def add_address(self, address):
        self.addresses.append(address)
        if self.nl:
            await self.nl.notify_newaddr(address)

    async def del_address(self, address):
        addr = self.lookup_address(address.iface, address.eid)
        if not addr:
            raise NetlinkError(errno.ENOENT)
        self.addresses.remove(addr)
        if self.nl:
            await self.nl.notify_deladdr(address)

    async def add_neighbour(self, neigh):
        if self.lookup_neighbour(neigh.iface, neigh.eid):
            raise NetlinkError(errno.EEXIST)
        self.neighbours.append(neigh)
        if self.nl:
            await self.nl.notify_newneigh(neigh)

    async def del_neighbour(self, neigh):
        neigh = self.lookup_neighbour(neigh.iface, neigh.eid)
        if not neigh:
            raise NetlinkError(errno.EENOENT)
        self.neighbours.remove(neigh)
        if self.nl:
            await self.nl.notify_delneigh(neigh)

    def find_interface_by_ifindex(self, ifindex):
        for i in self.interfaces:
            if i.ifindex == ifindex:
                return i
        return None

    def find_interface_by_name(self, name):
        for i in self.interfaces:
            if i.name == name:
                return i
        return None

    def lookup_route(self, net, eid):
        for rt in self.routes:
            eid_range = range(rt.start_eid, rt.end_eid + 1)
            if net in (0, rt.iface.net) and eid in eid_range:
                return rt
        return None

    def lookup_route_exact(self, iface, start_eid, end_eid):
        for rt in self.routes:
            if (rt.iface == iface and rt.start_eid == start_eid
                    and rt.end_eid == end_eid):
                return rt
        return None

    def lookup_neighbour(self, iface, eid):
        for neighbour in self.neighbours:
            if neighbour.iface == iface and neighbour.eid == eid:
                return neighbour
        return None

    def lookup_address(self, iface, eid):
        for address in self.addresses:
            if address.iface == iface and address.eid == eid:
                return address
        return None

    def find_endpoint(self, addr):
        iface = None
        lladdr = None
        if addr.is_ext:
            iface = self.find_interface_by_ifindex(addr.ifindex)
            lladdr = addr.lladdr
        else:
            route = self.lookup_route(addr.net, addr.eid)
            if route is None:
                return None
            iface = route.iface

            neigh = self.lookup_neighbour(route.iface, addr.eid)
            lladdr = neigh.lladdr

        if iface is None or lladdr is None:
            return None

        return iface, lladdr

    def dump(self):
        print("system:")
        if self.interfaces:
            print(" interfaces:")
            for i in self.interfaces:
                print(f"  {i}")
        if self.addresses:
            print(" addresses:")
            for a in self.addresses:
                print(f"  {a}")
        if self.routes:
            print(" routes:")
            for r in self.routes:
                print(f"  {r}")
        if self.neighbours:
            print(" neighbours:")
            for n in self.neighbours:
                print(f"  {n}")

class MCTPCommand:
    def __init__(self):
        self.send_channel, self.receive_channel = trio.open_memory_channel(0)

    async def complete(self, data):
        async with self.send_channel as chan:
            await chan.send(data)

    async def wait(self):
        async with self.receive_channel as chan:
            return await chan.receive()

class MCTPControlCommand(MCTPCommand):
    MSGTYPE = 0

    def __init__(self, rq, iid, cmd, data = bytes()):
        super().__init__()
        self.rq = rq
        self.iid = iid
        self.cmd = cmd
        self.data = data

    def to_buf(self):
        flags = self.iid
        if self.rq:
            flags = flags | 0x80
        return bytes([flags, self.cmd]) + self.data

class Endpoint:
    def __init__(self, iface, lladdr, ep_uuid = None, eid = 0, types = None):
        self.iface = iface
        self.lladdr = lladdr
        self.uuid = ep_uuid or uuid.uuid1()
        self.eid = eid
        self.types = types or [0]
        # keyed by (type, type-specific-instance)
        self.commands = {}

    def __str__(self):
        return f"uuid {self.uuid} lladdr {self.lladdr}, eid {self.eid}"

    def reset(self):
        self.eid = 0

    async def handle_mctp_message(self, sock, addr, data):
        if addr.type == 0:
            await self.handle_mctp_control(sock, addr, data)
        else:
            print(f"unknown MCTP message type {a.type}")

    async def handle_mctp_control(self, sock, addr, data):
        flags, opcode = data[0:2]
        rq = flags & 0x80
        iid = flags & 0x1f

        if not rq:
            cmd = self.commands.get((0, iid), None)
            assert cmd is not None, "unexpected response?"

            await cmd.complete(data)

        else:

            raddr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            # Use IID from request, zero Rq and D bits
            hdr = [iid, opcode]

            if opcode == 1:
                # Set Endpoint ID
                (op, eid) = data[2:]
                self.eid = eid
                data = bytes(hdr + [0x00, 0x00, self.eid, 0x00])
                await sock.send(raddr, data)

            elif opcode == 2:
                # Get Endpoint ID
                data = bytes(hdr + [0x00, self.eid, 0x00, 0x00])
                await sock.send(raddr, data)

            elif opcode == 3:
                # Get Endpoint UUID
                data = bytes(hdr + [0x00]) + self.uuid.bytes
                await sock.send(raddr, data)

            elif opcode == 5:
                # Get Message Type Support
                types = self.types
                data = bytes(hdr + [0x00, len(types)] + types)
                await sock.send(raddr, data)

            else:
                await sock.send(raddr, bytes(hdr + [0x05])) # unsupported command

    async def send_control(self, sock, cmd_code, data = bytes()):

        typ = MCTPControlCommand.MSGTYPE
        # todo: tag 0 implied
        addr = MCTPSockAddr(self.iface.net, self.eid, typ, 0x80)
        if sock.addr_ext:
            addr.set_ext(self.iface.ifindex, self.lladdr)

        # todo: multiple commands; iid 0 implied
        iid = 0
        cmd = MCTPControlCommand(True, iid, cmd_code, data)

        key = (typ, cmd.iid)
        assert not key in self.commands

        self.commands[key] = cmd

        await sock.send(addr, cmd.to_buf())

        return await cmd.wait()



class Network:
    def __init__(self):
        self.endpoints = []
        self.mctp_socket = None

    def add_endpoint(self, endpoint):
        self.endpoints.append(endpoint)

    def lookup_endpoint(self, iface, lladdr):
        for ep in self.endpoints:
            if ep.iface == iface and ep.lladdr == lladdr:
                return ep
        return None

    # register the core mctp control socket, on which incoming requests
    # are sent to mctpd
    def register_mctp_socket(self, socket):
        assert self.mctp_socket is None
        self.mctp_socket = socket

# MCTP-capable pyroute2 objects
class ifinfmsg_mctp(rtnl.ifinfmsg.ifinfmsg):
    class af_spec(netlink.nla):
        prefix = 'IFLA_'
        nla_map = (
            (AF_MCTP, 'AF_MCTP', 'af_spec_mctp'),
        )

        class af_spec_mctp(netlink.nla):
            prefix = 'IFLA_MCTP_'
            nla_map = (
                ('IFLA_MCTP_UNSPEC', 'none'),
                ('IFLA_MCTP_NET', 'uint32'),
            )

    class l2addr(netlink.nla_base):
        fields = [('value', 'c')]

class ifaddrmsg_mctp(rtnl.ifaddrmsg.ifaddrmsg):
    nla_map = (
        ('IFA_UNSPEC', 'hex'),
        ('IFA_ADDRESS', 'uint8'),
        ('IFA_LOCAL', 'uint8'),
        ('IFA_LABEL', 'asciiz'),
        ('IFA_BROADCAST', 'uint8'),
        ('IFA_ANYCAST', 'uint8'),
        ('IFA_CACHEINFO', 'cacheinfo'),
        ('IFA_MULTICAST', 'uint8'),
        ('IFA_FLAGS', 'uint32'),
    )

class ndmsg_mctp(rtnl.ndmsg.ndmsg):
    nla_map = (
        ('NDA_UNSPEC', 'none'),
        ('NDA_DST', 'uint8'),
        ('NDA_LLADDR', 'lladdr'),
        ('NDA_CACHEINFO', 'cacheinfo'),
        ('NDA_PROBES', 'uint32'),
        ('NDA_VLAN', 'uint16'),
        ('NDA_PORT', 'be16'),
        ('NDA_VNI', 'uint32'),
        ('NDA_IFINDEX', 'uint32'),
        ('NDA_MASTER', 'uint32'),
    )

    class lladdr(netlink.nla_base):
        fields = [('value', 'c')]

class rtmsg_mctp(rtnl.rtmsg.rtmsg):
    nla_map = (
        ('RTA_UNSPEC', 'none'),
        ('RTA_DST', 'uint8'),
        ('RTA_SRC', 'uint8'),
        ('RTA_IIF', 'uint32'),
        ('RTA_OIF', 'uint32'),
        ('RTA_GATEWAY', 'uint8'),
        ('RTA_PRIORITY', 'uint32'),
        ('RTA_PREFSRC', 'uint8'),
        ('RTA_METRICS', 'metrics'),
        ('RTA_MULTIPATH', '*get_nh'),
        ('RTA_PROTOINFO', 'uint32'),
        ('RTA_FLOW', 'uint32'),
        ('RTA_CACHEINFO', 'cacheinfo'),
        ('RTA_SESSION', 'hex'),
        ('RTA_MP_ALGO', 'hex'),
        ('RTA_TABLE', 'uint32'),
        ('RTA_MARK', 'uint32'),
        ('RTA_MFC_STATS', 'rta_mfc_stats'),
        ('RTA_VIA', 'rtvia'),
        ('RTA_NEWDST', 'uint8'),
        ('RTA_PREF', 'uint8'),
        ('RTA_ENCAP_TYPE', 'uint16'),
        ('RTA_ENCAP', 'encap_info'),
        ('RTA_EXPIRES', 'hex'),
    )

class BaseSocket:
    msg_fmt = "@I"

    def __init__(self, sock):
        self.sock = sock

    async def run(self):
        while True:
            data = await self.sock.recv(1024)
            if len(data) == 0:
                break

            await self.recv_msg(data)

    async def recv_msg(self, data):
        (typ,) = struct.unpack("@I", data[0:4])
        data = data[4:]
        if typ == 1:
            # send op
            addr = data[:MAX_SOCKADDR_SIZE]
            addrlen = int.from_bytes(
                    data[MAX_SOCKADDR_SIZE:MAX_SOCKADDR_SIZE+4],
                    byteorder = sys.byteorder
                )
            data = data[MAX_SOCKADDR_SIZE+4:]
            addr = addr[:addrlen]
            await self.handle_send(addr, data)
        elif typ == 2:
            # setsockopt op
            level, optname, optval = data[0:4], data[4:8], data[20:]
            level = int.from_bytes(level, byteorder = sys.byteorder)
            optname = int.from_bytes(optname, byteorder = sys.byteorder)
            await self.handle_setsockopt(level, optname, optval)
        elif typ == 3:
            # bind
            addr = data[:MAX_SOCKADDR_SIZE]
            addrlen = int.from_bytes(
                    data[MAX_SOCKADDR_SIZE:MAX_SOCKADDR_SIZE+4],
                    byteorder = sys.byteorder
                )
            addr = addr[:addrlen]
            await self.handle_bind(addr)

        else:
            print(f"unknown message type {typ}")

    async def send(self, addr, data):
        addrlen = len(addr)
        assert addrlen <= MAX_SOCKADDR_SIZE
        addr += b'\0' * (MAX_SOCKADDR_SIZE - addrlen)
        buf = struct.pack("@I", 0) + addr + struct.pack("@I", addrlen) + data
        await self.sock.send(buf)

    async def handle_bind(self, addr):
        pass

class MCTPSockAddr:
    base_addr_fmt = "@HHiBBBB"
    ext_addr_fmt = "@iB3c" # just the header here, we append the lladdr data

    @classmethod
    def parse(cls, data, ext):
        addrlen = len(data)
        baselen = struct.calcsize(cls.base_addr_fmt)
        extlen = struct.calcsize(cls.ext_addr_fmt)
        assert addrlen >= baselen
        base = data[:baselen]

        _, _, net, eid, type, tag, _ = struct.unpack(cls.base_addr_fmt, base)
        a = cls(net, eid, type, tag)

        if ext and addrlen >= extlen + baselen:
            ext = data[baselen:baselen + extlen]
            parts = struct.unpack(cls.ext_addr_fmt, ext)
            lladdr = data[baselen + extlen: baselen + extlen + parts[1]]
            a.set_ext(parts[0], lladdr)

        return a

    @classmethod
    def for_ep_resp(cls, ep, req_addr, ext):
        a = cls(ep.iface.net, ep.eid, req_addr.type, req_addr.tag ^ 0x80)
        if ext:
            a.set_ext(ep.iface.ifindex, ep.lladdr)
        return a

    def __init__(self, net, eid, type, tag):
        self.net = net
        self.eid = eid
        self.type = type
        self.tag = tag
        self.is_ext = False

    def set_ext(self, ifindex, lladdr):
        self.is_ext = True
        self.ifindex = ifindex
        self.lladdr = lladdr


    def to_buf(self):
        data = struct.pack(self.base_addr_fmt,
                AF_MCTP, 0, self.net, self.eid, self.type, self.tag, 0)
        if self.is_ext:
            # pad to MAX_ADDR_LEN
            lladdr_data = self.lladdr + bytes([0] * (32 - len(self.lladdr)))
            data += struct.pack(self.ext_addr_fmt,
                        self.ifindex, len(self.lladdr),
                        b'\0', b'\0', b'\0')
            data += lladdr_data
        return data

    def __str__(self):
        u = f"net {self.net} eid {self.eid} type {self.type} tag {self.tag}"
        if self.is_ext:
            u += f" ext {{ ifindex {self.ifindex} lladdr {self.lladdr} }}"
        return u


class MCTPSocket(BaseSocket):
    base_addr_fmt = "@HHIIBBBB"
    ext_addr_fmt = "@HHIIBBBBIBB32s"

    def __init__(self, sock, system, network):
        super().__init__(sock)
        self.addr_ext = False
        self.system = system
        self.network = network

    async def handle_send(self, addr, data):
        a = MCTPSockAddr.parse(addr, self.addr_ext)
        phys = self.system.find_endpoint(a)
        if phys is None:
            return

        ep = self.network.lookup_endpoint(*phys)
        if ep is None:
            return

        await ep.handle_mctp_message(self, a, data)

    async def handle_setsockopt(self, level, optname, optval):
        if level == 285 and optname == 1:
            val = int.from_bytes(optval, byteorder = sys.byteorder)
            self.addr_ext = bool(val)

    async def handle_bind(self, addr):
        self.network.register_mctp_socket(self)

    async def send(self, addr, data):
        addrbuf = addr.to_buf()
        addrlen = len(addrbuf)
        assert addrlen <= MAX_SOCKADDR_SIZE
        addrbuf += b'\0' * (MAX_SOCKADDR_SIZE - addrlen)
        buf = struct.pack("@I", 0) + addrbuf + struct.pack("@I", addrlen) + data
        await self.sock.send(buf)

class NLSocket(BaseSocket):
    addr_fmt = "@HHII"

    def __init__(self, sock, system):
        super().__init__(sock)
        self.addr_ext = False
        self.system = system
        system.nl = self

    def _create_msg(self, cls, type, flags):
        resp = cls()
        resp['header']['sequence_number'] = 0
        resp['header']['pid'] = 0
        resp['header']['type'] = type
        resp['header']['flags'] = flags
        return resp

    def _create_resp(self, cls, req, type, flags):
        resp = self._create_msg(cls, type, flags)
        resp['header']['sequence_number'] = req['header']['sequence_number']
        return resp

    def _append_nlmsg_done(self, buf, req):
        resp = netlink.nlmsg()
        resp['header']['sequence_number'] = req['header']['sequence_number']
        resp['header']['pid'] = 0
        resp['header']['type'] = netlink.NLMSG_DONE
        resp.encode()
        buf.extend(resp.data)

    async def _nlmsg_ack(self, req):
        resp = netlink.nlmsgerr()
        resp['header']['sequence_number'] = req['header']['sequence_number']
        resp['header']['pid'] = 0
        resp['header']['type'] = netlink.NLMSG_ERROR
        resp['error'] = 0
        resp.encode()
        await self._send_msg(resp.data)

    async def handle_send(self, addr, data):
        addr = addr[:struct.calcsize(self.addr_fmt)]
        addr = struct.unpack(self.addr_fmt, addr)
        msg = netlink.nlmsg(data)
        msg.decode()
        header = msg['header']
        typ = header['type']

        if not header['flags'] & netlink.NLM_F_REQUEST:
            print("error: not a request?");
            return

        if typ == rtnl.RTM_GETLINK:
            await self._handle_getlink(msg)
        elif typ == rtnl.RTM_GETADDR:
            await self._handle_getaddr(msg)

        elif typ == rtnl.RTM_GETROUTE:
            await self._handle_getroute(msg)
        elif typ == rtnl.RTM_NEWROUTE:
            await self._handle_newroute(msg)
        elif typ == rtnl.RTM_DELROUTE:
            await self._handle_delroute(msg)

        elif typ == rtnl.RTM_GETNEIGH:
            await self._handle_getneigh(msg)
        elif typ == rtnl.RTM_NEWNEIGH:
            await self._handle_newneigh(msg)
        elif typ == rtnl.RTM_DELNEIGH:
            await self._handle_delneigh(msg)

        else:
            print(f"unknown NL type {typ:x}")

    async def handle_setsockopt(self, level, optname, optval):
        pass

    async def _send_msg(self, buf):
        addr = struct.pack(self.addr_fmt, AF_NETLINK, 0, 0, 0)
        await self.send(addr, buf)

    async def _handle_getlink(self, msg):
        dump = bool(msg['header']['flags'] & netlink.NLM_F_DUMP)
        assert dump

        buf = bytearray()
        flags = netlink.NLM_F_MULTI if dump else 0

        ifaces = []
        if dump:
            ifaces = self.system.interfaces

        for iface in ifaces:
            resp = self._create_resp(ifinfmsg_mctp, msg, rtnl.RTM_NEWLINK, flags)
            resp['index'] = iface.ifindex
            resp['family'] = 0
            resp['type'] = ARPHRD_MCTP
            resp['flags'] = (
                rtnl.ifinfmsg.IFF_RUNNING |
                (rtnl.ifinfmsg.IFF_UP | rtnl.ifinfmsg.IFF_LOWER_UP
                    if iface.up else 0)
            )

            resp['attrs'] = [
                ['IFLA_IFNAME', iface.name],
                ['IFLA_ADDRESS', iface.lladdr],
                ['IFLA_MTU', iface.mtu],
                ['IFLA_MIN_MTU', iface.min_mtu],
                ['IFLA_MAX_MTU', iface.max_mtu],
                ['IFLA_AF_SPEC', {
                    'attrs': [['AF_MCTP', {
                        'attrs': [['IFLA_MCTP_NET', iface.net]],
                    }]],
                }],
            ]

            resp.encode()
            buf.extend(resp.data)

        self._append_nlmsg_done(buf, msg)
        await self._send_msg(buf)

    def _format_addr(self, msg, addr):
        msg['index'] = addr.iface.ifindex
        msg['family'] = AF_MCTP
        msg['prefixlen'] = 0
        msg['flags'] = 0
        msg['attrs'] = [
            ['IFA_LOCAL', addr.eid],
        ]

    async def _handle_getaddr(self, msg):
        dump = bool(msg['header']['flags'] & netlink.NLM_F_DUMP)
        assert dump

        buf = bytearray()
        flags = netlink.NLM_F_MULTI if dump else 0

        addrs = []
        if dump:
            addrs = self.system.addresses

        for addr in addrs:
            resp = self._create_resp(ifaddrmsg_mctp, msg,
                    rtnl.RTM_NEWADDR, flags)
            self._format_addr(resp, addr)
            resp.encode()
            buf.extend(resp.data)

        self._append_nlmsg_done(buf, msg)

        await self._send_msg(buf)

    async def _notify_addr(self, addr, typ):
        msg = self._create_msg(ifaddrmsg_mctp, typ, 0)
        self._format_addr(msg, addr)
        buf = bytearray()
        msg.encode()
        buf.extend(msg.data)
        await self._send_msg(buf)

    async def notify_newaddr(self, addr):
        await self._notify_addr(addr, rtnl.RTM_NEWADDR)

    async def notify_deladdr(self, addr):
        await self._notify_addr(addr, rtnl.RTM_DELADDR)

    def _format_neigh(self, msg, neigh):
        msg['ifindex'] = neigh.iface.ifindex
        msg['attrs'] = [
            ['NDA_DST', neigh.eid],
            ['NDA_LLADDR', neigh.lladdr],
        ]

    async def _handle_getneigh(self, msg):
        dump = bool(msg['header']['flags'] & netlink.NLM_F_DUMP)
        assert dump

        buf = bytearray()
        flags = netlink.NLM_F_MULTI if dump else 0

        if dump:
            neighbours = self.system.neighbours

        for n in neighbours:
            resp = self._create_resp(ndmsg_mctp, msg, rtnl.RTM_NEWNEIGH, flags)
            self._format_neigh(resp, n)
            resp.encode()
            buf.extend(resp.data)

        self._append_nlmsg_done(buf, msg)

        await self._send_msg(buf)

    async def _handle_newneigh(self, msg):
        # reparse as ndmsg
        msg = ndmsg_mctp(msg.data)
        msg.decode()

        ifindex = msg['ifindex']
        dst = msg.get_attr('NDA_DST')
        lladdr = msg.get_attr('NDA_LLADDR')

        iface = self.system.find_interface_by_ifindex(ifindex)
        neighbour = System.Neighbour(iface, lladdr, dst)
        try:
            await self.system.add_neighbour(neighbour)
        except NetlinkError as nle:
            msg = nle.to_nlmsg()
            msg.encode()
            await self._send_msg(msg.data)
            return

        if msg['header']['flags'] & netlink.NLM_F_ACK:
            await self._nlmsg_ack(msg)

    async def _handle_delneigh(self, msg):
        msg = ndmsg_mctp(msg.data)
        msg.decode()

        ifindex = msg['ifindex']
        dst = msg.get_attr('NDA_DST')
        lladdr = msg.get_attr('NDA_LLADDR')

        iface = self.system.find_interface_by_ifindex(ifindex)
        neighbour = System.Neighbour(iface, lladdr, dst)
        try:
            await self.system.del_neighbour(neighbour)
        except NetlinkError as nle:
            msg = nle.to_nlmsg()
            msg.encode()
            await self._send_msg(msg.data)
            return

        if msg['header']['flags'] & netlink.NLM_F_ACK:
            await self._nlmsg_ack(msg)

    async def _notify_neigh(self, neigh, typ):
        msg = self._create_msg(ifaddrmsg_mctp, typ, 0)
        self._format_neigh(msg, neigh)
        buf = bytearray()
        msg.encode()
        buf.extend(msg.data)
        await self._send_msg(buf)

    async def notify_delneigh(self, neigh):
        await self._notify_neigh(neigh, rtnl.RTM_DELNEIGH)

    async def notify_newneigh(self, neigh):
        await self._notify_neigh(neigh, rtnl.RTM_NEWNEIGH)

    def _format_route(self, msg, route):
        msg['family'] = AF_MCTP
        msg['dst_len'] = route.end_eid - route.start_eid
        msg['src_len'] = 0
        msg['attrs'] = [
            ['RTA_DST', route.start_eid],
            ['RTA_OIF', route.iface.ifindex],
            ['RTA_METRICS', {
                'attrs': [['RTAX_MTU', route.mtu]],
            }],
        ]

    async def _handle_getroute(self, msg):
        dump = bool(msg['header']['flags'] & netlink.NLM_F_DUMP)
        assert dump

        buf = bytearray()
        flags = netlink.NLM_F_MULTI if dump else 0

        if dump:
            routes = self.system.routes

        for route in routes:
            resp = self._create_resp(rtmsg_mctp, msg, rtnl.RTM_NEWROUTE, flags)
            self._format_route(self, resp, route)
            resp.encode()
            buf.extend(resp.data)

        self._append_nlmsg_done(buf, msg)

        await self._send_msg(buf)

    async def _handle_newroute(self, msg):
        msg = rtmsg_mctp(msg.data)
        msg.decode()

        ifindex = msg.get_attr('RTA_OIF')
        start_eid = msg.get_attr('RTA_DST')
        extent_eid = msg['dst_len']
        # todo: RTAX metrics
        mtu = 0

        iface = self.system.find_interface_by_ifindex(ifindex)
        route = System.Route(iface, start_eid, extent_eid)
        await self.system.add_route(route)

        if msg['header']['flags'] & netlink.NLM_F_ACK:
            await self._nlmsg_ack(msg)

    async def _handle_delroute(self, msg):
        msg = rtmsg_mctp(msg.data)
        msg.decode()

        ifindex = msg.get_attr('RTA_OIF')
        start_eid = msg.get_attr('RTA_DST')
        extent_eid = msg['dst_len']
        mtu = 0

        iface = self.system.find_interface_by_ifindex(ifindex)
        route = System.Route(iface, start_eid, extent_eid)
        try:
            await self.system.del_route(route)
        except NetlinkError as nle:
            msg = nle.to_nlmsg()
            msg.encode()
            await self._send_msg(msg.data)
            return

        if msg['header']['flags'] & netlink.NLM_F_ACK:
            await self._nlmsg_ack(msg)

    async def _notify_route(self, route, typ):
        msg = self._create_msg(ifaddrmsg_mctp, typ, 0)
        self._format_route(msg, route)
        buf = bytearray()
        msg.encode()
        buf.extend(msg.data)
        await self._send_msg(buf)

    async def notify_newroute(self, route):
        await self._notify_route(route, rtnl.RTM_NEWROUTE);

    async def notify_delroute(self, route):
        await self._notify_route(route, rtnl.RTM_DELROUTE);


async def send_fd(sock, fd):
    fdarray = array.array("i", [fd])
    await sock.sendmsg([b'x'], [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, fdarray),
        ]
    )


class MctpdWrapper:
    def __init__(self, bus, sysnet):
        self.bus = bus
        self.system = sysnet.system
        self.network = sysnet.network
        (self.sock_local, self.sock_remote) = self.socketpair()

    def socketpair(self):
        return trio.socket.socketpair(
                trio.socket.AF_UNIX,
                trio.socket.SOCK_SEQPACKET
            )

    async def handle_control(self, nursery):
        while True:
            data = await self.sock_local.recv(1024)
            if len(data) == 0:
                break
            op = data[0]
            if op == 0x00:
                # init
                await self.sock_local.send(b'a')

            elif op == 0x01:
                # MCTP socket()
                (local, remote) = self.socketpair()
                sd = MCTPSocket(local, self.system, self.network)
                await send_fd(self.sock_local, remote.fileno())
                remote.close()
                nursery.start_soon(sd.run)

            elif op == 0x02:
                # NL socket()
                (local, remote) = self.socketpair()
                nl = NLSocket(local, self.system)
                await send_fd(self.sock_local, remote.fileno())
                remote.close()
                nursery.start_soon(nl.run)

            else:
                print(f"unknown op {op}")

    async def start_mctpd(self, nursery):
        nursery.start_soon(self.handle_control, nursery)
        self.proc = await nursery.start(self.mctpd_proc, nursery)

    def stop_mctpd(self):
        if self.proc:
            self.proc.terminate()

    async def mctpd_proc(self, nursery, task_status = trio.TASK_STATUS_IGNORED):
        # We want to start the mctpd process, but not return before it's
        # ready to interact with our test via dbus.
        #
        # So, we spawn the process here asynchronously, then monitor dbus for
        # the Name Owner Changed signal that indicates that it has registered
        # itself.
        busobj = await self.bus.get_proxy_object(
                'org.freedesktop.DBus',
                '/org/freedesktop/DBus'
            )
        interface = await busobj.get_interface('org.freedesktop.DBus')

        s = trio.Semaphore(initial_value = 0)
        def name_owner_changed(name, new_owner, old_owner):
            if name == 'au.com.codeconstruct.MCTP1':
                s.release()

        await interface.on_name_owner_changed(name_owner_changed)

        # start mctpd, passing our control socket
        env = os.environ.copy()
        env['MCTP_TEST_SOCK'] = str(self.sock_remote.fileno())
        proc = await trio.lowlevel.open_process(
                ['./test-mctpd', '-v'], # todo: flexible paths
                pass_fds = (1, 2, self.sock_remote.fileno()),
                env = env,
            )
        self.sock_remote.close()

        # wait for name to appear, cancel NameOwnerChanged listener
        await s.acquire()
        await interface.off_name_owner_changed(name_owner_changed)

        # The proc argument here will be passed as the return value for
        # nursery.start. The caller will want this to terminate the
        # process after the test has run.
        task_status.started(proc)

        await proc.wait()

Sysnet = namedtuple('SysNet', ['system', 'network'])

"""Simple system & network.

Contains one interface (lladdr 0x10, local EID 8), and one endpoint (lladdr
0x1d), that reports support for MCTP control and PLDM.
"""
@pytest.fixture
async def sysnet():
    system = System()
    iface = System.Interface('mctp0', 1, 1, bytes([0x10]), 68, 254, True)
    await system.add_interface(iface)
    await system.add_address(System.Address(iface, 8))

    network = Network()
    network.add_endpoint(Endpoint(iface, bytes([0x1d]), types = [0, 1]))

    return Sysnet(system, network)

@pytest.fixture
async def dbus():
    async with asyncdbus.MessageBus().connect() as bus:
        yield bus

@pytest.fixture
async def mctpd(nursery, dbus, sysnet):
    m = MctpdWrapper(dbus, sysnet)
    await m.start_mctpd(nursery)
    yield m
    m.stop_mctpd()
