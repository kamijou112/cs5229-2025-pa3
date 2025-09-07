#!/usr/bin/env python3

# Copyright 2023 Intel Corporation
# Copyright 2025 National University of Singapore
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Andy Fingerhut, andy.fingerhut@gmail.com

import os
import logging

import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest

from scapy.all import *

# Links to many Python methods useful when writing automated tests:

# The package `ptf.testutils` contains many useful Python methods for
# writing automated tests, some of which are demonstrated below with
# calls prefixed by the local alias `tu.`.  You can see the
# definitions for all Python code in this package, including some
# documentation for these methods, here:

# https://github.com/p4lang/ptf/blob/master/src/ptf/testutils.py


######################################################################
# Configure logging
######################################################################

# Note: I am not an expert at configuring the Python logging library.
# Recommendations welcome on improvements here.

# The effect achieved by the code below seems to be that many DEBUG
# and higher priority logging messages go to the console, and also to
# a file named 'ptf.log'.  Some of the messages written to the
# 'ptf.log' file do not go to the console, and appear to be created
# from within the ptf library.

logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Examples of some kinds of calls that can be made to generate
# logging messages.
#logger.debug("10 logger.debug message")
#logger.info("20 logger.info message")
#logger.warn("30 logger.warn message")
#logger.error("40 logger.error message")
#logging.debug("10 logging.debug message")
#logging.info("20 logging.info message")
#logging.warn("30 logging.warn message")
#logging.error("40 logging.error message")

def set_thresholds(hh_threshold, drop_threshold):
    # update thresholds
    current_path = os.path.abspath(os.path.dirname(__file__))
    assert os.path.basename(current_path) == 'ptf', \
        "Expected path to be ptf, got %s. \
                Are you running run_ptf.sh from the exercise's root directory?" % current_path

    # got to one hierarchy up, trim off ptf
    current_path = os.path.dirname(current_path)
    print()

    # go to util/monitoring_util
    util_path = os.path.join(current_path, 'monitoring_util')
    monitoring_util_path = os.path.join(util_path, 'monitoring_util')
    if not os.path.exists(monitoring_util_path):
        os.system(f"cd {util_path} && make && chmod +x monitoring_util")
    os.system(f"sudo {monitoring_util_path} -hht {hh_threshold} -dt {drop_threshold}")

class MonitoringTest(BaseTest):
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        logging.debug("MonitoringTest.setUp()")

    def tearDown(self):
        logging.debug("MonitoringTest.tearDown()")

class FwdTest(MonitoringTest):
    def runTest(self):
        in_smac = '08:00:00:00:01:11'
        in_dmac = '08:00:00:00:02:22'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 0
        eg_port = 1

        # h1 can reach h2
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        # h2 can reach h1
        in_smac = '08:00:00:00:02:22'
        in_dmac = '08:00:00:00:01:11'

        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.1'

        ig_port = 1
        eg_port = 0

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

class ReportHhOnceTest(MonitoringTest):
    def runTest(self):
        HH_THRESHOLD = 3
        DROP_THRESHOLD = 6
        set_thresholds(HH_THRESHOLD, DROP_THRESHOLD)

        in_smac = '08:00:00:00:01:11'
        in_dmac = '08:00:00:00:02:22'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 0
        eg_port = 1
        mirr_port = 2

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   tcp_sport=53, tcp_dport=6666)
        for i in range(1, HH_THRESHOLD + 2):
            tu.send_packet(self, ig_port, pkt)
            if i == HH_THRESHOLD + 1:
                tu.verify_packet(self, pkt, mirr_port)
            else:
                tu.verify_no_packet(self, pkt, mirr_port)

class DnsAttackDropTest(MonitoringTest):
    def runTest(self):
        HH_THRESHOLD = 3
        DROP_THRESHOLD = 6
        set_thresholds(HH_THRESHOLD, DROP_THRESHOLD)

        in_smac = '08:00:00:00:02:22'
        in_dmac = '08:00:00:00:01:11'

        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.1'

        ig_port = 1
        eg_port = 0

        pkt = tu.simple_udp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   udp_sport=6666, udp_dport=53)
        tu.send_packet(self, ig_port, pkt)

        in_smac = '08:00:00:00:01:11'
        in_dmac = '08:00:00:00:02:22'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 0
        eg_port = 1
        mirr_port = 2

        pkt = tu.simple_udp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   udp_sport=53, udp_dport=6666)
        for i in range(1, DROP_THRESHOLD + 4):
            tu.send_packet(self, ig_port, pkt)
            # +1 because we sent a request above
            if i > DROP_THRESHOLD + 1: 
                tu.verify_no_packet(self, pkt, eg_port)
            else:
                tu.verify_packet(self, pkt, eg_port)

verify_count = 0
expected_hh = []
rcvd_hh = []
def check_pkt(pkt):
    global verify_count
    global rcvd_hh
    global expected_hh
    if ICMP in pkt:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst,str(0), str(0), pkt[IP].proto])
    elif TCP in pkt:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst, str(pkt[TCP].sport), str(pkt[TCP].dport), str(pkt[IP].proto)])
    else:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst, str(pkt[UDP].sport), str(pkt[UDP].dport), str(pkt[IP].proto)])
    print(f"Received HH report: {rcvd}")
    assert not rcvd in rcvd_hh
    assert rcvd in expected_hh
    rcvd_hh.append(rcvd)
    verify_count = verify_count + 1


class SampleTraceTest(MonitoringTest):
    def runTest(self):
        HH_THRESHOLD = 50
        DROP_THRESHOLD = 100
        TOP_K_HH = 5

        set_thresholds(HH_THRESHOLD, DROP_THRESHOLD)

        ig_port = 0
        eg_port = 1

        global verify_count
        global rcvd_hh
        global expected_hh

        gt = []
        with open('./ptf/test-trace-gt.csv') as f:
            gt = f.read()
        gt = gt.split('\n')
        
        for i in range(len(gt)):
            entry = gt[i].split(' ')[0]
            count = int(gt[i].split(' ')[1])
            entry = entry.split(',')
            entry[2] = str(int(float(entry[2])))
            entry[3] = str(int(float(entry[3])))
            entry[4] = str(int(float(entry[4])))
            if count > HH_THRESHOLD:
                expected_hh.append(','.join(entry))
            else:
                break
        assert len(expected_hh) == TOP_K_HH

        pkts = []
        with open('./ptf/test-trace.csv') as f:
            pkts = f.read()
        pkts = pkts.split('\n')

        t = AsyncSniffer(iface="veth5", prn=check_pkt, count=TOP_K_HH, timeout=30)
        t.start()

        time.sleep(1)

        ctr = 0
        for pkt in pkts:
            pkt = pkt.split(',')
            src_ip = pkt[0]
            dst_ip = pkt[1]
            src_port = int(float(pkt[2]))
            dst_port = int(float(pkt[3]))
            proto = int(float(pkt[4]))
            pkt =  Ether(src="ee:30:ca:9d:1e:00", dst="08:00:00:00:02:22")
            if proto == 1:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / ICMP()
            elif proto == 6:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
            else:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
            tu.send_packet(self, ig_port, pkt)
            time.sleep(0.01)
            # ctr += 1
            # if ctr % 100 == 0:
            #     print(ctr)
        
        time.sleep(1)

        t.join()
        assert verify_count == TOP_K_HH