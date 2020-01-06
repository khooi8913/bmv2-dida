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

#define BL_STAGE_SIZE 3200
#define BL_CELL_BIT_WIDTH 32

#define BL_INIT(num) register<bit<BL_CELL_BIT_WIDTH>>(BL_STAGE_SIZE) bl##num

#define BL_READ(num, ip, seed) hash(meta.index_bl##num, HashAlgorithm.crc32, (bit<32>)0, {ip, seed}, (bit<32>)BL_STAGE_SIZE);\
bl##num.read(meta.value_bl##num, meta.index_bl##num)

/* CONTROL PLANE VARIABLES */
register <bit<32>>(1)   SUSPICIOUS_THRESHOLD;
register <bit<32>>(1)   BLCOUNT;

/* Initialize CMS */
SKETCH_INIT(0);
SKETCH_INIT(1);
SKETCH_INIT(2);
SKETCH_INIT(3);
SKETCH_INIT(4);
SKETCH_INIT(5);

/* Initialize BL */
BL_INIT(0);
BL_INIT(1);
BL_INIT(2);
BL_INIT(3);

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

    action increment_black_list_count() {
        bit<32> tmpBlackListCount;
        BLCOUNT.read(tmpBlackListCount, 0);
        if (meta.addedToBl == 1) {
            tmpBlackListCount = tmpBlackListCount + 1;
        }
        BLCOUNT.write(0, tmpBlackListCount);
    }

    action verify_traffic_source () {
        meta.blDiff = 1; // Init

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
        
        if(diff0 == 0 || diff1 == 0 || diff2 == 0 || diff3 == 0){
            meta.blDiff = 0;
        } else{
            meta.blDiff = 1;
        }
        // if(diff0 == 0) {
        //     meta.blDiff = 0;
        // } else if(diff1 == 0) {
        //     meta.blDiff = 0;
        // }else if(diff2 == 0) {
        //     meta.blDiff = 0;
        // } else if(diff3 == 0) {
        //     meta.blDiff = 0;
        // } else {
        //     meta.blDiff = 1; // Init
        // }
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
            1 : forward(2);
            2 : forward(1);
        }
    }

    apply {
        direct_forward.apply();

        if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
            // Border needs to check whether the traffic is allowed or not
            verify_traffic_source();
            if(meta.blDiff == 0) {  // If source IP is in the black list
                drop();
            }
        } else if (hdr.ctrl.isValid() && hdr.ctrl.flag == ControlMessageType.CONTROL){
            // Control header, and make sure that the flag is set as a control
            // Add to black list
            // add_black_list_entry();
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
            // drop by the PRE
            drop();
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

    action sketch_count_border() {
        SKETCH_COUNT(0, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_COUNT(1, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_COUNT(2, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xCCCCCCCCCCCCCCCC);
        SKETCH_COUNT(3, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xDDDDDDDDDDDDDDDD);
        SKETCH_COUNT(4, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xEEEEEEEEEEEEEEEE);
        SKETCH_COUNT(5, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xFFFFFFFFFFFFFFFF);
    }

    action mark_suspicious_traffic () {
        SUSPICIOUS_THRESHOLD.read(meta.suspicious_threshold, 0);

        meta.sketch_min = 1<<31;
        SKETCH_MIN(0, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xAAAAAAAAAAAAAAAA);
        SKETCH_MIN(1, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xBBBBBBBBBBBBBBBB);
        SKETCH_MIN(2, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xCCCCCCCCCCCCCCCC);
        SKETCH_MIN(3, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xDDDDDDDDDDDDDDDD);
        SKETCH_MIN(4, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xEEEEEEEEEEEEEEEE);
        SKETCH_MIN(5, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, 64w0xFFFFFFFFFFFFFFFF);

        if(meta.sketch_min > meta.suspicious_threshold) {
            meta.suspicious = 1;
        } else {
            return;   
        }
    }

    action encapsulate_ctrl_hdr() {
        hdr.ctrl.setValid();
        // hdr.ctrl.routerId = meta.routerId;
        hdr.ctrl.routerId = 8w0x1;
        hdr.ctrl.counterValue = meta.sketch_min;
        hdr.ctrl.flag = ControlMessageType.NOTIFICATION;
        hdr.ethernet.etherType = TYPE_CTRL;
    }

    table count_responses {
        key = {
            hdr.ipv4.fragOffset : exact;
            hdr.udp.srcPort : exact;
        }
        actions = {
            sketch_count_border;
            NoAction;
        }
        const entries = {
            (0, 53) : sketch_count_border();
        }
        default_action = NoAction;
    }

    apply {
        count_responses.apply();
        mark_suspicious_traffic();
        if(meta.suspicious == 1) {
            encapsulate_ctrl_hdr();
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
