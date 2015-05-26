#!/usr/bin/env python2
# -*- encoding: utf-8 -*-
# TopologyScanner.py
'''
Final project for Data Communication 1 & 2.
Copyright (C) 2015 - Matías A. Ré Medina
UNICEN Systems Engineering student.
'''

import subprocess
from lxml import etree

class TopologyParser(object):

    def __init__(self, filename):
        self.filename = filename
        self.data = {}
        self.loif = self.tsharkD()
        self.parseXML()

    def parseXML(self):
        parser = etree.XMLParser()
        tree = etree.parse(self.filename, parser)
        nodes = tree.xpath("/Scenario/NetworkPlan/Node")
        for node in nodes:
            name, nid, ntype = node.get('id'), node.get('name'), node.get('type')
            ifaces = node.xpath("interface")
            for iface in ifaces:
                ifname = iface.get('name')
                mac, ipv4, ipv6 = iface.xpath("address")
                mac, ipv4, ipv6 = mac.text, ipv4.text, ipv6.text
                self.data.update({name: [nid, ifname, ntype, ipv4, ipv6, mac]})

    def tsharkD(self): 
        return subprocess.check_output(["tshark", "-D"], stderr=subprocess.STDOUT)

    def printIfaces(self):
        print "[+] Current local interfaces:"
        for x in self.loif.split("\n"):
            sp = x.split()
            if len(sp) == 2:
                ifid, ifname = sp
            elif len(sp) == 3:
                ifid, ifname, ifalias = sp
            try:
                ifname = ifname[:ifname.index(".", 3)]
            except:
                pass
            
            print ifid, ifname

    def printData(self):
        print "[+] XML topology basic nodes configuration."
        for node in self.data:
            print node, self.data.get(node)

    def printInfo(self):
        self.printData()
        print
        self.printIfaces()