/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"

/* CONSTANTS */
// #define SKETCH_ROW_LENGTH 4096
// #define SKETCH_CELL_BIT_WIDTH 32

// #define SKETCH_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) sketch##num

// #define SKETCH_COUNT(num, ip1, ip2, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip1, ip2, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
//  sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
//  meta.value_sketch##num = meta.value_sketch##num +1; \
//  sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

// #define SKETCH_MIN(num, ip1, ip2, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip1, ip2, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
//  sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
//  meta.sketch_min = meta.value_sketch##num < meta.sketch_min ? meta.value_sketch##num : meta.sketch_min

// /* Initialize CMS */
// SKETCH_INIT(0);
// SKETCH_INIT(1);
// SKETCH_INIT(2);
// SKETCH_INIT(3);
// SKETCH_INIT(4);
// SKETCH_INIT(5);

/* MACROS */
#define SKETCH_ROW_LENGTH 8160
#define SKETCH_CELL_BIT_WIDTH 32

#define SKETCH_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) sketch##num
#define WINDOW_INIT(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_ROW_LENGTH) window##num

#define SKETCH_INDEX(num, ip, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)SKETCH_ROW_LENGTH)
#define SKETCH_COUNT(num, ip, seed) SKETCH_INDEX(num, ip, seed); \
sketch##num.read(meta.value_sketch##num, meta.index_sketch##num);\
window##num.read(meta.window_sketch##num, meta.index_sketch##num); \
meta.value_sketch##num = (meta.value_sketch##num >> (bit<8>)(meta.mAbsWindowId-meta.window_sketch##num));\
meta.value_sketch##num = meta.value_sketch##num + 1;\
meta.window_sketch##num = meta.mAbsWindowId;\
sketch##num.write(meta.index_sketch##num, meta.value_sketch##num);\
window##num.write(meta.index_sketch##num, meta.window_sketch##num);
#define SKETCH_MIN(num, ip, seed) hash(meta.index_sketch##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)SKETCH_ROW_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 window##num.read(meta.window_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = (meta.value_sketch##num >> (bit<8>)(meta.mAbsWindowId-meta.window_sketch##num));\
 meta.sketch_min = meta.value_sketch##num < meta.sketch_min ? meta.value_sketch##num : meta.sketch_min


/* Initialize SkAge */
SKETCH_INIT(0);
WINDOW_INIT(0);
SKETCH_INIT(1);
WINDOW_INIT(1);
SKETCH_INIT(2);
WINDOW_INIT(2);

/* CONTROL PLANE VARIABLES */
register <bit<32>>(1)   ATTACK_THRESHOLD;

/* Wrap around */
const bit<32> WINDOWS_PER_PHASE = 10; // # of entries in the TCAM
register <bit<32>> (1) GLOBAL_WINDOW_ID;
register <bit<32>> (1) WRAP_AROUND_CONSTANT;


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

    action extract_flow_id () {
        // meta.flowId[103:72] = hdr.ipv4.srcAddr;
        // meta.flowId[71:40] = hdr.ipv4.dstAddr;
        meta.flowId[103:72] = hdr.ipv4.dstAddr;
        meta.flowId[71:40] = hdr.ipv4.srcAddr;
        meta.flowId[39:32] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[31:16] = hdr.tcp.dstPort; 
            meta.flowId[15:0] = hdr.tcp.srcPort;
            // meta.flowId[31:16] = hdr.tcp.srcPort;
            // meta.flowId[15:0] = hdr.tcp.dstPort;
        } else if(hdr.udp.isValid()) {
            meta.flowId[31:16] = hdr.udp.dstPort;
            meta.flowId[15:0] = hdr.udp.srcPort;
            // meta.flowId[31:16] = hdr.udp.srcPort;
            // meta.flowId[15:0] = hdr.udp.dstPort;
        } else {
            meta.flowId[31:16] = 0;
            meta.flowId[15:0] = 0;
        }
    }
    
    action get_absolute_window_id(bit<32> absWinId){
        bit<32> wrapAroundConstant;
        WRAP_AROUND_CONSTANT.read(wrapAroundConstant, 0);

        bit<32> globalWinId;
        GLOBAL_WINDOW_ID.read(globalWinId, 0);

        bit <32> tempWinId;
        tempWinId = absWinId + wrapAroundConstant;

        if (tempWinId < globalWinId) {
            wrapAroundConstant = wrapAroundConstant + WINDOWS_PER_PHASE;
        }

        tempWinId = absWinId + wrapAroundConstant;

        globalWinId = tempWinId;
        meta.mAbsWindowId = globalWinId;
        GLOBAL_WINDOW_ID.write(0, globalWinId);
        WRAP_AROUND_CONSTANT.write(0, wrapAroundConstant);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mark_attack_traffic() {
        ATTACK_THRESHOLD.read(meta.attack_threshold, 0);
        meta.sketch_min = 1<<31;
        SKETCH_MIN(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_MIN(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_MIN(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);

        if(hdr.ctrl.counterValue - meta.sketch_min > meta.attack_threshold || meta.sketch_min - hdr.ctrl.counterValue > meta.attack_threshold) {
            meta.blDetected = TrafficType.ATTACK;
        }
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table get_window_id {
        key = {     
            standard_metadata.ingress_global_timestamp : range;
        }
        actions = {
            get_absolute_window_id;
            NoAction;
        }
        const entries = {
            #include "../include/window_id.p4"
        }
        default_action = NoAction();
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            forward;
        }
        default_action = forward(9w3);

        const entries = {
            32w0xc0a80101: forward(9w1);
            32w0xc0a80102: forward(9w2);
        }
    }

    apply {
        get_window_id.apply();
        ipv4_forward.apply();

        if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
            NoAction();
        } else if(hdr.ctrl.isValid() && hdr.ctrl.flag == ControlMessageType.NOTIFICATION) {
            // If there is a control packet...
            // Check the response counts received from Border against query counts in Access
            mark_attack_traffic();
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
    
    action extract_flow_id () {
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
    
    action sketch_count_access() {
        SKETCH_COUNT(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_COUNT(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_COUNT(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);
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
