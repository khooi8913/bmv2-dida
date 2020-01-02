/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            default : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6     : parse_tcp;
            8w17    : parse_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ethernet.etherType) {
            TYPE_CTRL : parse_ctrl;
            default   : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ethernet.etherType) {
            TYPE_CTRL : parse_ctrl;
            default   : accept;
        }
    }

    state parse_ctrl {
        packet.extract(hdr.ctrl);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.ctrl);
    }
}
