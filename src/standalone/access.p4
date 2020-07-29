/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"

/* MACROS */
#define SKETCH_ROW_LENGTH 8160
#define SKETCH_CELL_BIT_WIDTH 32

#define SKETCH_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) sketch##num
#define WINDOW_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) window##num

#define SKETCH_INDEX(num, ip, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)SKETCH_ROW_LENGTH)
#define SKETCH_COUNT(num, ip, seed) SKETCH_INDEX(num, ip, seed); \
sketch##num.read(meta.value_sketch##num, meta.index_sketch##num);\
window##num.read(meta.window_sketch##num, meta.index_sketch##num); \
meta.value_sketch##num = (meta.window_sketch##num == meta.current_tstamp) ? meta.value_sketch##num + 1 : 1;\
meta.window_sketch##num = meta.current_tstamp;\
sketch##num.write(meta.index_sketch##num, meta.value_sketch##num);\
window##num.write(meta.index_sketch##num, meta.window_sketch##num);
#define SKETCH_MIN(num, ip, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
window##num.read(meta.window_sketch##num, meta.index_sketch##num); \
meta.value_sketch##num = (meta.window_sketch##num == meta.current_tstamp) ? meta.value_sketch##num : 0;\
meta.window_sketch##num = meta.current_tstamp;\
meta.sketch_min = meta.value_sketch##num < meta.sketch_min ? meta.value_sketch##num : meta.sketch_min;\
sketch##num.write(meta.index_sketch##num, meta.value_sketch##num);\
window##num.write(meta.index_sketch##num, meta.window_sketch##num);


/* Initialize SkAge */
SKETCH_INIT(0);
WINDOW_INIT(0);
SKETCH_INIT(1);
WINDOW_INIT(1);
SKETCH_INIT(2);
WINDOW_INIT(2);

/* CONTROL PLANE VARIABLES */
register <bit<32>>(1)   ATTACK_THRESHOLD;

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action extract_flow_id_req () {
        meta.flowId[103:72] = hdr.ipv4.srcAddr;
        meta.flowId[71:40] = hdr.ipv4.dstAddr;
        meta.flowId[39:32] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[31:16] = hdr.tcp.srcPort;
            meta.flowId[15:0] = hdr.tcp.dstPort;
        } else if(hdr.udp.isValid()) {
            meta.flowId[31:16] = hdr.udp.srcPort;
            meta.flowId[15:0] = hdr.udp.dstPort;
        } else {
            meta.flowId[31:16] = 0;
            meta.flowId[15:0] = 0;
        }
    }

    action extract_flow_id_resp () {
        meta.flowId[103:72] = hdr.ipv4.dstAddr;
        meta.flowId[71:40] = hdr.ipv4.srcAddr;
        meta.flowId[39:32] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[31:16] = hdr.tcp.dstPort;
            meta.flowId[15:0] = hdr.tcp.srcPort;
        } else if(hdr.udp.isValid()) {
            meta.flowId[31:16] = hdr.udp.dstPort;
            meta.flowId[15:0] = hdr.udp.srcPort;
        } else {
            meta.flowId[31:16] = 0;
            meta.flowId[15:0] = 0;
        }
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action check_if_attack() {
        ATTACK_THRESHOLD.read(meta.attack_threshold, 0);
        if(hdr.ctrl.counter_val - meta.sketch_min > meta.attack_threshold || meta.sketch_min - hdr.ctrl.counter_val > meta.attack_threshold) {
            meta.is_attack = 1;
        }
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action markRequests(){
        meta.is_request = 1;
    }

    action markCtrl() {
        meta.is_ctrl = 1;
    }
    
    action ctrlIndexHash() {
        extract_flow_id_resp();
    }
    
    action reqIndexHash() {
        extract_flow_id_req();
    }

    action markAttack() {
        hdr.ctrl.flag = 0xAAAA;
        hdr.ipv4.dstAddr = hdr.ctrl.source_rtr_id;
        hdr.ctrl.counter_val = 0;
        hdr.ctrl.tstamp_val = 0;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        bit<48> temp;
        temp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = temp;
    }

    action unMarkAttack() {
        hdr.ctrl.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            NoAction;
            forward;
        }
        default_action = forward(9w3);

        const entries = {
            32w0xc0a80101: forward(9w1);
            32w0xc0a80102: forward(9w2);
        }
    }

    table mark_packet {
        key = {
            hdr.ipv4.fragOffset : ternary;
            hdr.udp.dstPort : ternary;
            hdr.ctrl.flag : ternary;
        }
        actions = {
            NoAction;
            markRequests;
            markCtrl;
        }
        default_action = NoAction;
        const entries = {
            (0, 53, _) : markRequests();
            (_, _, 0xFFFF) : markCtrl();
        }
    }

    table extract_flow_id {
        key = {
            meta.is_ctrl : ternary;
            meta.is_request : ternary;
        }
        actions = {
            NoAction;
            ctrlIndexHash;
            reqIndexHash;
        }
        const entries = {
            (1, _) : ctrlIndexHash;
            (_, 1) : reqIndexHash;
        }
    }

    table mark_attack {
        key = {
            meta.is_attack : exact;
        }
        actions = {
            unMarkAttack;
            markAttack;
        }
        const entries = {
            0 : unMarkAttack;
            1 : markAttack;
        }
    }

    apply {
        meta.current_tstamp = (bit<32>)standard_metadata.ingress_global_timestamp[47:22];
        ipv4_forward.apply();
        mark_packet.apply();

        // init val
        meta.is_attack = 0;

        // extract flow ID
        extract_flow_id.apply();

        if(meta.is_request == 1) {
            // count here
            SKETCH_COUNT(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
            SKETCH_COUNT(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
            SKETCH_COUNT(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);
        } else if(meta.is_ctrl == 1) {
            if(hdr.ctrl.tstamp_val == meta.current_tstamp) {
                // check the counts
                meta.sketch_min = 1<<31;
                SKETCH_MIN(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
                SKETCH_MIN(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
                SKETCH_MIN(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);

                // verify if attack here
                check_if_attack();
            }
        }
        // mark or unmark traffic
        mark_attack.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
