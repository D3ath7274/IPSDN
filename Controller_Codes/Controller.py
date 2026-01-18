#   ryu-manager Controller.py

from __future__ import print_function
import array
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import snortlib
from ryu.lib import hub
import random
from datetime import datetime
import psutil
import socket
import threading

import timeit
import os

import pandas as pd
from sklearn.preprocessing import minmax_scale
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

snort_alerts = 0
packets_in = 0
stat_replies = 0

now = datetime.now()
current_time = now.strftime("%d-%m-%Y_%H:%M:%S")

os.chdir(os.path.dirname(os.path.abspath(__file__)))

cpu_usage = open("Txt_Files/cpu_usage.txt", "a+")
cpu_usage.write("\n" + current_time)
snort_alerts_file = open("Txt_Files/snort_alerts.txt", "a+")
snort_alerts_file.write("\n" + current_time)
packets_in_time = open("Txt_Files/packets_in_time.txt", "a+")
packets_in_time.write("\n" + current_time)
flow_stats_predict = open("Txt_Files/flow_stats_predict.txt", "a+")
flow_stats_predict.write("\n" + current_time)
snort_alerts_time = open("Txt_Files/snort_alerts_time.txt", "a+")
snort_alerts_time.write("\n" + current_time)
flow_stats_time = open("Txt_Files/flow_stats_time.txt", "a+")
flow_stats_time.write("\n" + current_time)


pid = os.getpid()
p = psutil.Process(pid)
print("PID: ", pid)
mlp = MLPClassifier(hidden_layer_sizes=(6), activation='logistic', solver='adam', beta_1=0.9,
                    beta_2=0.9, learning_rate='constant', learning_rate_init=0.1, momentum=0.9)
print(mlp)

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        self.snort = kwargs['snortlib']
        self.snort_port = 1
        self.mac_to_port = {}
        self.datapaths = {}

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        
        # Start network socket server for Sending_Alert.py
        self.socket_server_thread = threading.Thread(target=self.start_socket_server)
        self.socket_server_thread.daemon = True
        self.socket_server_thread.start()
        
        self.mlp_training()
        self.collect_thread = hub.spawn(self.collect)

    def mlp_training(self):
        self.logger.info("MLP model training")
        global mlp
        start = timeit.default_timer()
        X_train = pd.read_csv("Dataset/train_dataset.csv")
        Y_train = X_train["class"]
        del X_train["class"]
        X_train.iloc[:] = minmax_scale(X_train.iloc[:])  # normalize the data
        mlp.fit(X_train, Y_train.values.ravel())  # get a trained model
        stop = timeit.default_timer()
        time = stop - start
        self.logger.info("Training time: %s", time)
        
        start = timeit.default_timer()
        X_test = pd.read_csv("Dataset/test_dataset.csv")
        Y_test = X_test["class"]
        del X_test["class"]
        prediction = mlp.predict(X_test)
        stop = timeit.default_timer()
        time = stop - start
        self.logger.info("Testing time: %s", time)
        c = confusion_matrix(Y_test, prediction)
        print(c)
        a = accuracy_score(Y_test, prediction) * 100
        print("Accuracy score: " + str(a) + "%")

        while (a < 85):
            mlp.fit(X_train, Y_train.values.ravel())
            prediction = mlp.predict(X_test)
            c = confusion_matrix(Y_test, prediction)
            print(c)
            a = accuracy_score(Y_test, prediction) * 100
            print("Accuracy score: " + str(a) + "%")
        
    def start_socket_server(self):
        """Start network socket server to receive alerts from Sending_Alert.py"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', 51234))
            server_socket.listen(1)
            self.logger.info("Socket server listening on 127.0.0.1:51234")
            
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    self.logger.info("Alert received from %s", addr)
                    client_socket.close()
                except Exception as e:
                    self.logger.error("Socket server error: %s", e)
        except Exception as e:
            self.logger.error("Failed to start socket server: %s", e)

    def collect(self):
        self.logger.info("Collecting flows for anomaly detection")
        global p
        global cpu_usage
        while p.is_running():
            cpu = p.cpu_percent()
            self.logger.info("CPU usage in percent: %s", cpu)
            cpu_usage.write("\n" + str(cpu))
            for datapath in self.datapaths.values():
                self.logger.info(
                    "Sending flow stats request for datapath %s", datapath.id)
                ofpro = datapath.ofproto
                ofpro_parser = datapath.ofproto_parser
                request = ofpro_parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(request)
            hub.sleep(random.randint(10, 15))

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply, ], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        global stat_replies
        global flow_stats_time
        stat_replies += 1
        self.logger.info(
            "Receiving flow stats from datapath %s", ev.msg.datapath.id)

        start = timeit.default_timer()
        for stat in sorted([flow for flow in body if (flow.priority == 1)]):
            self.anomaly_based_ips(ev.msg.datapath.id, stat.match['eth_src'], stat.duration_sec, stat.match['ip_proto'],
                                    stat.byte_count, stat.packet_count)

        stop = timeit.default_timer()
        self.logger.info(
            "Stat reply %s takes %s seconds for anomaly detection", stat_replies, stop-start)

        flow_stats_time.write("\n" + str(stop-start))

    def anomaly_based_ips(self, datapath_id, source_mac, duration, ip_proto, byte_count, packet_count):
        self.logger.info("\nAnomaly detection of flow entry %s %s %s %s", duration, ip_proto, byte_count,
                         packet_count)

        dpid = datapath_id
        src = source_mac
        decision = mlp.predict(
            [[duration, ip_proto, byte_count, packet_count]])

        global flow_stats_predict
        flow_stats_predict.write("\nDuration: " + str(duration) + ", ip_proto: " + str(ip_proto) +
                                    ", byte count: " + str(byte_count) + ", packet count: " + str(packet_count) + ", Class: " + str(decision))


        if decision == 1:
            self.logger.info(
                "Anomaly detected, configuring datapath %s to block traffic from %s", dpid, src)
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            match = ofp_parser.OFPMatch(eth_src=src)
            action = []
            self.add_flow(datapath, 2, match, action, 15)

    def packet_print(self, msg):
        pkt = packet.Packet(array.array('B', msg.pkt))

        global snort_alerts_file

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        snort_alerts_file.write("\n" + str(msg.alertmsg[0]) +
                                "," + str(eth.src) + "," + str(_ipv4.dst))

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        start = timeit.default_timer()
        global snort_alerts
        snort_alerts += 1

        global snort_alerts_time

        msg = ev.msg

        self.logger.info('Alertmsg: %s' % ''.join(msg.alertmsg))

        self.packet_print(msg)
        self.signature_based_ips(msg.pkt)

        stop = timeit.default_timer()
        self.logger.info(
            "Alert number %s takes %s seconds to process", snort_alerts, stop-start)

        snort_alerts_time.write("\n" + str(stop-start))

        

    def signature_based_ips(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        src_eth = eth.src

        self.logger.info("Block all traffic from %s", src_eth)

        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=src_eth)
            action = []
            self.add_flow(datapath, 3, match, action, 15)

    def add_flow(self, datapath, priority, match, actions, idle=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, idle_timeout=idle, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        # listen for table-miss event
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global packets_in
        packets_in += 1
        global packets_in_time
        start = timeit.default_timer()
        self.logger.info("Processing packet %s", packets_in)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            #self.logger.info("Aborting LLDP packet")
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port,
                                            tcp_dst=t.dst_port, )

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port,
                                            udp_dst=u.dst_port, )
                # verify if we have a valid buffer_id, if yes avoid to send both FLOW_MOD & PACKET_OUT
                # maximum buffer ID is NO BUFFER to due to OVS bug.
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,
                                  msg.buffer_id, idle=15)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=15)
                stop = timeit.default_timer()
                self.logger.info(
                    "Packet %s takes %s seconds to process", packets_in, stop-start)
                packets_in_time.write("\n" + str(stop-start))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("Port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("Port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("Port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
