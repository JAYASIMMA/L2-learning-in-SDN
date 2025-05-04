from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response

# REST API URL
REST_API_URL = '/firewall/rules'

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SwitchController, {'switch_app': self})
        self.firewall_rules = []  # list of (src, dst)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if (src, dst) in self.firewall_rules:
            # Drop packet
            return

        out_port = self.mac_to_port[dpid].get(dst, datapath.ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)


class SwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SwitchController, self).__init__(req, link, data, **config)
        self.switch_app = data['switch_app']

    @route('firewall', REST_API_URL, methods=['POST'])
    def add_rule(self, req, **kwargs):
        try:
            rule = req.json if req.body else {}
            src = rule.get('src')
            dst = rule.get('dst')
            if src and dst:
                self.switch_app.firewall_rules.append((src, dst))
                return Response(status=200, body=json.dumps({'result': 'Rule added'}))
            return Response(status=400, body=json.dumps({'error': 'Missing src or dst'}))
        except Exception as e:
            return Response(status=500, body=json.dumps({'error': str(e)}))