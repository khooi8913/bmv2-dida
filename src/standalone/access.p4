/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"

/* CONSTANTS */
#define SKETCH_ROW_LENGTH 4096
#define SKETCH_CELL_BIT_WIDTH 32

#define SKETCH_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) sketch##num

#define SKETCH_COUNT(num, ip1, ip2, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip1, ip2, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = meta.value_sketch##num +1; \
 sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

#define SKETCH_MIN(num, ip1, ip2, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip1, ip2, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.sketch_min = meta.value_sketch##num < meta.sketch_min ? meta.value_sketch##num : meta.sketch_min

/* CONTROL PLANE VARIABLES */
register <bit<32>>(1)   ATTACK_THRESHOLD;

/* Initialize CMS */
SKETCH_INIT(0);
SKETCH_INIT(1);
SKETCH_INIT(2);
SKETCH_INIT(3);
SKETCH_INIT(4);
SKETCH_INIT(5);

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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mark_attack_traffic() {
        ATTACK_THRESHOLD.read(meta.attack_threshold, 0);
        meta.sketch_min = 1<<31;
        SKETCH_MIN(0, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_MIN(1, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_MIN(2, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xCCCCCCCCCCCCCCCC);
        SKETCH_MIN(3, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xDDDDDDDDDDDDDDDD);
        SKETCH_MIN(4, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xEEEEEEEEEEEEEEEE);
        SKETCH_MIN(5, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xFFFFFFFFFFFFFFFF);

        if(hdr.ctrl.counterValue - meta.sketch_min > meta.attack_threshold || meta.sketch_min - hdr.ctrl.counterValue > meta.attack_threshold) {
            meta.blDetected = TrafficType.ATTACK;
        }
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table direct_forward {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            forward;
            NoAction;
        }
        default_action = NoAction;

        const entries = {
            9w1: forward(9w2);
            9w2: forward(9w1);
            9w3: forward(9w1);
        }
    }

    apply {
        direct_forward.apply();

        if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
            NoAction();
        } else if(hdr.ctrl.isValid() && hdr.ctrl.flag == ControlMessageType.NOTIFICATION) {
            // If there is a control packet...
            // Check the response counts received from Border against query counts in Access
            mark_attack_traffic();
            // debug.apply();
            if(meta.blDetected == TrafficType.ATTACK) {
                standard_metadata.egress_spec = standard_metadata.ingress_port;;
            }
        } else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action sketch_count_access() {
        SKETCH_COUNT(0, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_COUNT(1, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_COUNT(2, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xCCCCCCCCCCCCCCCC);
        SKETCH_COUNT(3, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xDDDDDDDDDDDDDDDD);
        SKETCH_COUNT(4, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xEEEEEEEEEEEEEEEE);
        SKETCH_COUNT(5, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 64w0xFFFFFFFFFFFFFFFF);
    }

    action sketch_count_border() {
        SKETCH_COUNT(0, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_COUNT(1, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_COUNT(2, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xCCCCCCCCCCCCCCCC);
        SKETCH_COUNT(3, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xDDDDDDDDDDDDDDDD);
        SKETCH_COUNT(4, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xEEEEEEEEEEEEEEEE);
        SKETCH_COUNT(5, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xFFFFFFFFFFFFFFFF);
    }

    action set_invalid_ctrl_hdr() {
        hdr.ctrl.setInvalid();
    }

    table count_requests {
        key = {
            hdr.ipv4.fragOffset : exact;
            hdr.udp.dstPort : exact;
        }
        actions = {
            sketch_count_access;
            NoAction;
        }
        const entries = {
            (0, 53) : sketch_count_access();
        }
        default_action = NoAction;
    }

    apply {
        count_requests.apply();
        if(meta.blDetected == TrafficType.ATTACK) {
            // Prepare control packet to be sent back to Border to blocking
            // get_border_router_ip.apply();
            meta.routerIp = 32w0x01010101;
            hdr.ctrl.flag = ControlMessageType.CONTROL;
            hdr.ipv4.dstAddr = meta.routerIp;
        } else {
            // TrafficType.NORMAL, invalidate control header
            set_invalid_ctrl_hdr();
            // Restore EtherType to IPV4
            hdr.ethernet.etherType = TYPE_IPV4;
        }
    }
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
