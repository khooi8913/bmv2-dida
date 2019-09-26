/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_CTRL = 0x1234;

const bit<32> COUNTERS_PER_TABLE = 32w1024;
const bit<32> HASH_MIN = 32w0;
const bit<32> HASH_MAX = 32w1023;

const bit<16> DNS_PORT_NUMBER = 53;

const bit<32> THRESHOLD = 10;
const bit<32> NUM_ROUTERS = 32;  

// Have to manually configure
// 0 for Edge, 1 for TotR
register <bit<1>> (1)   OP_MODE;
// ID for this device
register <bit<8>> (1)  ROUTER_ID;

// Register definition
// HashPipe
// Table 1
register <bit<80>> (COUNTERS_PER_TABLE) s1FlowTracker;
register <bit<32>> (COUNTERS_PER_TABLE) s1PacketCount;
register <bit<1>> (COUNTERS_PER_TABLE) s1ValidBit;
// Table 2
register <bit<80>> (COUNTERS_PER_TABLE) s2FlowTracker;
register <bit<32>> (COUNTERS_PER_TABLE) s2PacketCount;
register <bit<1>> (COUNTERS_PER_TABLE) s2ValidBit;

// Blacklist table
register <bit<32>> (COUNTERS_PER_TABLE) BlackList;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header ctrl_t {
    bit<8>  routerId;
    bit<8>  flag;   // 1 means notification, 0 means control
    bit<32> counterValue;
}

struct metadata {
    bit<80>     flowId;
    bit<32>     s1Index;
    bit<32>     s2Index;
    bit<80>     mKeyCarried;
    bit<32>     mCountCarried;
    bit<1>      mOpMode;
    bit<32>     blCounterCarried;
    bit<32>     blFlowId;
    bit<32>     blIndex;
    bit<32>     blDiff;
    bit<1>      blDetected;
    bit<32>     routerIp;
    bit<8>      routerId;

    ip4Addr_t   srcIp;
    ip4Addr_t   dstIp;
    bit<16>     srcPort;
    bit<16>     dstPort;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    icmp_t      icmp;
    tcp_t       tcp;
    udp_t       udp; 
    ctrl_t      ctrl;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
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
            8w1     : parse_icmp;
            8w6     : parse_tcp;
            8w17    : parse_udp;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
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

    action ipv4_forward (macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    action bIngress_get_flow_id () {
        meta.blFlowId[31:0] = hdr.ipv4.srcAddr;
    }

    action bIngress_compute_hash_index () {
        hash(
            meta.blIndex, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.blFlowId, 
                80w0xFFFFFFFFFFFFFFFFFFFF
            },
            HASH_MAX
        );
    }
    
    action bIngress_check_black_list () {
        bit<32> tmp;
        BlackList.read(tmp, meta.blIndex);
        meta.blDiff = tmp - meta.blFlowId;
    }

    action aIngress_get_flow_id () {
        meta.flowId[31:0] = hdr.ipv4.dstAddr;
        meta.flowId[63:32] = hdr.ipv4.srcAddr;
        meta.flowId[79:64] = hdr.udp.dstPort;
    }

    action aIngress_compute_index () {
        hash(
            meta.s1Index, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId, 
                80w0xFFFFFFFFFFFFFFFFFFFF
            },
            HASH_MAX
        );
        
        hash(
            meta.s2Index, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId
            },
            HASH_MAX
        );
    }

    action aIngress_count_check () {
        bit<80> s1FlowId; 
        bit<32> s1PktCount;
        
        bit<80> s2FlowId; 
        bit<32> s2PktCount;

        s1FlowTracker.read(s1FlowId, meta.s1Index);
        s1PacketCount.read(s1PktCount, meta.s1Index);

        s2FlowTracker.read(s2FlowId, meta.s2Index);
        s2PacketCount.read(s2PktCount, meta.s2Index);

        meta.blDetected = 0;

        if((meta.flowId - s1FlowId) != 0 && (meta.flowId - s2FlowId) != 0) {
            // detected flow does not exist in table!
            // hence it is unsolicited
            meta.blDetected = 1;
        } else {
            if(meta.flowId - s1FlowId == 0) {
                if (hdr.ctrl.counterValue > s1PktCount) {
                    meta.blDetected = 1;
                }
            } else {
                // check s2
                if (meta.flowId - s2FlowId == 0) {
                    if (hdr.ctrl.counterValue > s2PktCount) {
                        meta.blDetected = 1;
                    }
                }
            }
        }
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // table debug {
    //     key = {
    //         meta.srcIp : exact;
    //         meta.dstIp : exact;
    //         meta.srcPort : exact;
    //         meta.dstPort : exact;
    //         meta.flowId : exact;
    //     }
    //     actions = {
    //         NoAction;
    //     }
    //     default_action = NoAction;
    // }
 
    apply {
        // meta.srcIp = hdr.ipv4.srcAddr;
        // meta.dstIp = hdr.ipv4.dstAddr;
        // meta.srcPort = hdr.udp.srcPort;
        // meta.dstPort = hdr.udp.dstPort;

        ipv4_lpm.apply();
        OP_MODE.read(meta.mOpMode, 0);

        if(meta.mOpMode == 0) {
            // Border
            if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
                // Normal IPv4 Packets
                bIngress_get_flow_id();
                bIngress_compute_hash_index();  
                // Border needs to check whether the traffic is allowed or not        
                bIngress_check_black_list();
                if(meta.blDiff == 0) {
                    // If source IP is in the black list
                    drop();
                }
            } else if (hdr.ctrl.isValid() && hdr.ctrl.flag == 0){
                // Control header, and make sure that the flag is set as a control
                bIngress_get_flow_id();
                bIngress_compute_hash_index();
                // Add to black list
                BlackList.write(meta.blIndex, meta.blFlowId);
                // drop by the PRE
                drop(); 
            } else {
                drop();
            }
        } else {
            // Access
            if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
                NoAction();
            } else if(hdr.ctrl.isValid() && hdr.ctrl.flag == 1) {
                // If there is a control packet...
                // Check the response counts received from Border against query counts in Access
                aIngress_get_flow_id();
                aIngress_compute_index();
                aIngress_count_check();
                // debug.apply();
                if(meta.blDetected == 1) {
                    standard_metadata.egress_spec = standard_metadata.ingress_port;;
                }
            } else {
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

    action extract_flow_id () {
        if(meta.mOpMode == 0) {
            // Border
            meta.flowId[31:0] = hdr.ipv4.dstAddr;
            meta.flowId[63:32] = hdr.ipv4.srcAddr;
            meta.flowId[79:64] = hdr.udp.dstPort;
        } else {
            // Access
            meta.flowId[31:0] = hdr.ipv4.srcAddr;
            meta.flowId[63:32] = hdr.ipv4.dstAddr;
            meta.flowId[79:64] = hdr.udp.srcPort;
        }
    }

    action compute_index () {
        hash(
            meta.s1Index, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId, 
                80w0xFFFFFFFFFFFFFFFFFFFF
            },
            HASH_MAX
        );
        
        hash(
            meta.s2Index, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId
            },
            HASH_MAX
        );
    }

    // variable declarations, should they be here?
    // have to check again whether this is valid or not
    bit<80>  mDiff;
    bit<32>  mIndex;

    bit<80>  mKeyToWrite;
    bit<32>  mCountToWrite;
    bit<1>   mBitToWrite;

    bit<80>  mKeyTable;
    bit<32>  mCountTable;
    bit<1>   mValid;

    action bEgress_encap_control (bit<32> countValue) {
        hdr.ethernet.etherType = TYPE_CTRL;
        hdr.ctrl.setValid();
        ROUTER_ID.read(hdr.ctrl.routerId, 0);
        hdr.ctrl.counterValue = countValue;
        hdr.ctrl.flag = 1;  
    }

    action hashpipe_stage_1 () {
        meta.mKeyCarried = meta.flowId;
        meta.mCountCarried = 1;
        mIndex = meta.s1Index;
        mDiff = 0;

        // read the key value at that location
        s1FlowTracker.read(mKeyTable, mIndex);
        s1PacketCount.read(mCountTable, mIndex);
        s1ValidBit.read(mValid, mIndex);
        
        // always insert at first stage
        mKeyToWrite = meta.mKeyCarried;
        mCountToWrite = meta.mCountCarried;
        mBitToWrite = 1;

        if(mValid == 1) {
            // check whether they are different
            mDiff = mKeyTable - meta.mKeyCarried;
            mCountToWrite = (mDiff == 0) ? mCountTable + 1 : mCountToWrite;
        } 

        // update hash tables
        s1FlowTracker.write(mIndex, mKeyToWrite);
        s1PacketCount.write(mIndex, mCountToWrite);
        s1ValidBit.write(mIndex, mBitToWrite);

        // update metadata carried to the next table stage
        meta.mKeyCarried = (mDiff == 0) ? 0 : mKeyTable;
        meta.mCountCarried = (mDiff == 0) ? 0 : mCountTable;

        // check whether count has exceeded threshold
        // scenarios to be considered
        // insert new key, evict old key - never exceed threshold
        // increment counter of current key - possible to exceed threshold
        // insert to new slot - will never exceed threshold
        if (mCountToWrite > THRESHOLD) {
            meta.blCounterCarried = mCountToWrite;
        }
    }

    action hashpipe_stage_2 () {
        // mKeyCarried is set
        // mCountCarried is set
        mIndex = meta.s2Index;
        mDiff = 0;

        // init
        mKeyToWrite = 0;
        mCountToWrite = 0;
        mBitToWrite = 0;
        
        // read the key, value at mIndex
        s2FlowTracker.read(mKeyTable, mIndex);
        s2PacketCount.read(mCountTable, mIndex);
        s2ValidBit.read(mValid, mIndex);

        // if the slot is empty
        if (mValid != 1) {
            mDiff = 1;
            mKeyToWrite = meta.mKeyCarried;
            mCountToWrite = meta.mCountCarried;
            mBitToWrite = 1;
        } else {
            mDiff = meta.mKeyCarried - mKeyTable;
            // same key, increase count
            if(mDiff == 0) {
                mKeyToWrite = mKeyTable;
                mCountToWrite = mCountTable + meta.mCountCarried;
            } else {
                // different key
                // compare the count values
                if (meta.mCountCarried > mCountTable) {
                    // evict the key with smaller count value
                    mKeyToWrite = meta.mKeyCarried;
                    mCountToWrite = meta.mCountCarried;
                    mBitToWrite = 1;
                } else {
                    // no eviction occurs
                    mDiff = 0;
                }
            }
        }       

        // if no eviction, maintain current key, value, and metadata
        if (mDiff == 0) {
            mKeyToWrite = mKeyTable;
            mCountToWrite = mCountTable;
            mBitToWrite = mValid;
        } else {
            // if eviction occurs, have to update metadata 
            meta.mKeyCarried = mKeyTable;
            meta.mCountCarried = mCountTable;
        }

        // update hash tables
        s2FlowTracker.write(mIndex, mKeyToWrite);
        s2PacketCount.write(mIndex, mCountToWrite);
        s2ValidBit.write(mIndex, mBitToWrite);

        // check whether count has exceeded threshold
        // possible scenarios
        // 1. evicted key 
        //      a. insert into new slot --> will never exceed threshold
        //      b. increment a current key --> may exceed threshold
        //      c. evict current key and insert --> will never exceed threshold
        if (mCountToWrite > THRESHOLD) {
            meta.blCounterCarried = mCountToWrite;
        }
    }

    // HashPipe implementation here (d=2)
    action hashpipe() {
        hashpipe_stage_1();
        hashpipe_stage_2();
    }

    action set_invalid_ctrl_hdr() {
        hdr.ctrl.setInvalid();
    }

    action router_id_to_router_ip (ip4Addr_t routerIp) {
        meta.routerIp = routerIp;
    }

    table border_router_ip {
        key = {
            hdr.ctrl.routerId : exact;
        }
        actions = {
            router_id_to_router_ip;
            NoAction;
        }
        const entries = {
            (8w0x1) : router_id_to_router_ip(32w0x01010101);
            (8w0x2) : router_id_to_router_ip(32w0x02020202);
        }
        default_action = NoAction();
    }

    apply {
        // Extract flowId for processing
        extract_flow_id();
        compute_index();

        if(meta.mOpMode == 0) {
            // Border
            if (!hdr.icmp.isValid() && hdr.udp.srcPort == DNS_PORT_NUMBER) {
                hashpipe();
            }
            // If threshold exceeded, append notification header
            if(meta.blCounterCarried !=0) {
                bEgress_encap_control(meta.blCounterCarried);
            }
        } else {
            // Access
            if(hdr.ctrl.isValid() && hdr.ctrl.flag == 1) {
                // Incoming notification message
                if(meta.blDetected == 1) {
                    // If confirmed as unsolicited source
                    // Prepare control packet to be sent back to Border to blocking
                    border_router_ip.apply();
                    hdr.ctrl.flag = 0;
                    ROUTER_ID.read(hdr.ctrl.routerId, 0);
                    hdr.ipv4.dstAddr = meta.routerIp;
                } else {
                    // if normal traffic, discard control header
                    // reset etherType back to IPv4 and before forwarding
                    set_invalid_ctrl_hdr();
                    hdr.ethernet.etherType = TYPE_IPV4;
                }
            } else {
                // normal = true;
                if (!hdr.icmp.isValid() && hdr.udp.dstPort == DNS_PORT_NUMBER) {
                    hashpipe();
                }
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.ctrl);
    }
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
