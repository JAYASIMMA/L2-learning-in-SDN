from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

REST_URL = '/firewall/rules'

class RestFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.firewall_rules = []  # List of (src_mac, dst_mac)
        wsgi = kwargs['wsgi']
        wsgi.register(FirewallController, {'firewall_app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Firewall rule: drop packet
        if (src, dst) in self.firewall_rules:
            self.logger.info("Blocked by firewall: %s -> %s", src, dst)
            return

        out_port = self.mac_to_port[dpid].get(dst, datapath.ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
        self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.firewall_app = data['firewall_app']

    @route('firewall', REST_URL, methods=['POST'])
    def add_firewall_rule(self, req, **kwargs):
        try:
            rule = req.json if req.body else {}
            src = rule.get('src')
            dst = rule.get('dst')
            if src and dst:
                self.firewall_app.firewall_rules.append((src, dst))
                return Response(status=200,
                                content_type='application/json',
                                body=json.dumps({'status': 'Rule added'}))
            else:
                return Response(status=400,
                                content_type='application/json',
                                body=json.dumps({'error': 'src and dst required'}))
        except Exception as e:
            return Response(status=500,
                            content_type='application/json',
                            body=json.dumps({'error': str(e)}))
