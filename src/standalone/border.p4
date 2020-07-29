/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"

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

#define BL_STAGE_SIZE 3200
#define BL_CELL_BIT_WIDTH 32

#define BL_INIT(num) register<bit<BL_CELL_BIT_WIDTH>>(BL_STAGE_SIZE) bl##num

#define BL_READ(num, ip, seed) hash(meta.index_bl##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)BL_STAGE_SIZE);\
bl##num.read(meta.value_bl##num, meta.index_bl##num)

/* Initialize BL */
BL_INIT(0);
BL_INIT(1);
BL_INIT(2);
BL_INIT(3);

/* CONTROL PLANE VARIABLES */
register <bit<32>>(1)   SUSPICIOUS_THRESHOLD;
register <bit<32>>(1)   BLCOUNT;

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

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action extract_flow_id () {
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

    action increment_black_list_count() {
        bit<32> tmpBlackListCount;
        BLCOUNT.read(tmpBlackListCount, 0);
        if (meta.addedToBl == 1) {
            tmpBlackListCount = tmpBlackListCount + 1;
        }
        BLCOUNT.write(0, tmpBlackListCount);
    }

    action verify_traffic_source () {
        meta.is_bl = 1; // Init

        BL_READ(0, hdr.ipv4.srcAddr, 32w0xAAAAAAAA);
        BL_READ(1, hdr.ipv4.srcAddr, 32w0xBBBBBBBB);
        BL_READ(2, hdr.ipv4.srcAddr, 32w0xCCCCCCCC);
        BL_READ(3, hdr.ipv4.srcAddr, 32w0xDDDDDDDD);

        bit<32> diff0;
        bit<32> diff1;
        bit<32> diff2;
        bit<32> diff3;
        diff0 = hdr.ipv4.srcAddr - meta.value_bl0;
        diff1 = hdr.ipv4.srcAddr - meta.value_bl1;
        diff2 = hdr.ipv4.srcAddr - meta.value_bl2;
        diff3 = hdr.ipv4.srcAddr - meta.value_bl3;
        
        if(diff0 == 0 || diff1 == 0 || diff2 == 0 || diff3 == 0) {
            meta.is_bl = 0;
        } else{
            meta.is_bl = 1;
        }
    }

    action check_if_suspicious () {
        SUSPICIOUS_THRESHOLD.read(meta.suspicious_threshold, 0);

        meta.sketch_min = 1<<31;
        SKETCH_MIN(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_MIN(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_MIN(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);

        if(meta.sketch_min > meta.suspicious_threshold) {
            meta.is_suspicious = 1;
        } else {
            meta.is_suspicious = 0;
        }
    }

    action markSuspicious() {
        hdr.ctrl.setValid();
        hdr.ethernet.etherType = TYPE_CTRL;
        hdr.ctrl.flag = 0xFFFF; // send this to access
        hdr.ctrl.counter_val = meta.sketch_min;
        hdr.ctrl.tstamp_val = meta.current_tstamp;
        hdr.ctrl.source_rtr_id = 32w0xc0a80101; // router id is hard coded for now
    }

    action markResponses(){
        meta.is_response = 1;
    }

    action markCtrl() {
        meta.is_ctrl = 1;
    }

    table mark_packet {
        key = {
            hdr.ipv4.fragOffset : ternary;
            hdr.udp.srcPort : ternary;
            hdr.ctrl.flag : ternary;
        }
        actions = {
            NoAction;
            markResponses;
            markCtrl;
        }
        default_action = NoAction;
        const entries = {
            (_, _, 0xAAAA) : markCtrl();
            (0, 53, _) : markResponses();
        }
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            forward;
        }
        default_action = forward(9w2);

        const entries = {
            32w0xc0a80101: forward(9w1);
            32w0xc0a80102: forward(9w1);
        }
    }

    table mark_suspicious {
        key = {
            meta.is_suspicious : exact;
        }
        actions = {
            markSuspicious;
            NoAction;
        }
        const entries = {
            1 : markSuspicious();
        }
    }

    table filter_traffic {
        key = {
            meta.is_bl : exact;
            hdr.udp.srcPort : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (0, 53) : drop();
        }
    }

    apply {
        meta.current_tstamp = (bit<32>)standard_metadata.ingress_global_timestamp[47:22];
        ipv4_forward.apply();
        mark_packet.apply();

        meta.is_suspicious = 0;

        verify_traffic_source();
        filter_traffic.apply();

        if(meta.is_response == 1 || meta.is_ctrl == 1 ){
            if(meta.is_response == 1) {
                extract_flow_id();
                SKETCH_COUNT(0, meta.flowId, 64w0xAAAAAAAAAAAAAAAA);
                SKETCH_COUNT(1, meta.flowId, 64w0xBBBBBBBBBBBBBBBB);
                SKETCH_COUNT(2, meta.flowId, 64w0xCCCCCCCCCCCCCCCC);
                check_if_suspicious();
                mark_suspicious.apply();
            } else if(meta.is_ctrl == 1) {
                // append to bl
                bit<32> ipToWrite;

                BL_READ(0, hdr.ipv4.srcAddr, 32w0xAAAAAAAA);
                BL_READ(1, hdr.ipv4.srcAddr, 32w0xBBBBBBBB);
                BL_READ(2, hdr.ipv4.srcAddr, 32w0xCCCCCCCC);
                BL_READ(3, hdr.ipv4.srcAddr, 32w0xDDDDDDDD);

                ipToWrite = 0;
                if(meta.value_bl0 == 0 && meta.addedToBl == 0) {
                    ipToWrite = hdr.ipv4.srcAddr;
                    meta.addedToBl = 1;
                } else {
                    ipToWrite = meta.value_bl0;
                }
                bl0.write(meta.index_bl0, ipToWrite);

                ipToWrite = 0;
                if(meta.value_bl1 == 0 && meta.addedToBl == 0) {
                    ipToWrite = hdr.ipv4.srcAddr;
                    meta.addedToBl = 1;
                } else {
                    ipToWrite = meta.value_bl1;
                }
                bl1.write(meta.index_bl1, ipToWrite);

                ipToWrite = 0;
                if(meta.value_bl2 == 0 && meta.addedToBl == 0) {
                    ipToWrite = hdr.ipv4.srcAddr;
                    meta.addedToBl = 1;
                } else {
                    ipToWrite = meta.value_bl2;
                }
                bl2.write(meta.index_bl2, ipToWrite);

                ipToWrite = 0;
                if(meta.value_bl3 == 0 && meta.addedToBl == 0) {
                    ipToWrite = hdr.ipv4.srcAddr;
                    meta.addedToBl = 1;
                } else {
                    ipToWrite = meta.value_bl3;
                }
                bl3.write(meta.index_bl3, ipToWrite);

                // Increment black list count                
                increment_black_list_count();
                drop();            
            }    
        } 
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
