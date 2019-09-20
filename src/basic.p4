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
// Table 1
register <bit<80>> (COUNTERS_PER_TABLE) s1FlowTracker;
register <bit<32>> (COUNTERS_PER_TABLE) s1PacketCount;
register <bit<1>> (COUNTERS_PER_TABLE) s1ValidBit;
// Table 2
register <bit<80>> (COUNTERS_PER_TABLE) s2FlowTracker;
register <bit<32>> (COUNTERS_PER_TABLE) s2PacketCount;
register <bit<1>> (COUNTERS_PER_TABLE) s2ValidBit;

// Blacklist table
register <bit<80>> (COUNTERS_PER_TABLE) BlackListTracker;

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
    bit<32>     hhIndex;
    bit<80>     hhDiff;
    bit<32>     hhCounterCarried;
    bit<1>      hhDetected;
    bit<32>     routerIp;
    bit<8>      routerId;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    ctrl_t      ctrl;
    tcp_t       tcp;
    udp_t       udp; 
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
            TYPE_IPV4   : parse_ipv4;
            TYPE_CTRL   : parse_ctrl;
        }
    }

    state parse_ctrl {
        packet.extract(hdr.ctrl);
        transition parse_ipv4;
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
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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

    action extract_flow_id() {
        // Recirculated packet from TotR
        meta.flowId[31:0] = hdr.ipv4.srcAddr;
    }
    
    action compute_index () {
        hash(
            meta.hhIndex, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId, 
                80w0xFFFFFFFFFFFFFFFFFFFF
            },
            HASH_MAX
        );
    }

    action ipv4_forward (macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }
    
    action check_hh_table () {
        bit<80> tmp;
        BlackListTracker.read(tmp, meta.hhIndex);
        meta.hhDiff = tmp - meta.flowId;
    }

    table hh_table {
        actions = {
            check_hh_table();
        }   
        default_action = check_hh_table();
    }

    table drop_hh {
        actions = {
            drop;
        }
        default_action = drop();
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
 
    apply {
        ipv4_lpm.apply();
        extract_flow_id();
        // only source address is important
        compute_index();

        OP_MODE.read(meta.mOpMode, 0);
        if(meta.mOpMode == 0) {
            // 0 for Edge
            // Normal IPv4 Packets
            if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
                // Edge needs to check whether the traffic is allowed or not        
                hh_table.apply();
                // If it is malicious flow
                if(meta.hhDiff == 0) {
                    drop_hh.apply();
                }
            } else if (hdr.ctrl.isValid() && hdr.ctrl.flag == 0){
                // Control header, and make sure that the flag is set as a control

                drop(); // drop by the PRE
                // add to drop table
                BlackListTracker.write(meta.hhIndex, meta.flowId);
            } else {
                drop();
            }
        } else {
            // 1 for TotR
            if(hdr.ipv4.isValid() && !hdr.ctrl.isValid()) {
                // Do nothing
            } else if(hdr.ctrl.isValid() && hdr.ctrl.flag == 1) {
                // If there is a control packet...
                
            } else {
                drop();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

// HashPipe implementation here (d=2)
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action extract_flow_id () {
        if(meta.mOpMode == 0) {
            // Edge
            meta.flowId[31:0] = hdr.ipv4.dstAddr;
            meta.flowId[63:32] = hdr.ipv4.srcAddr;
            meta.flowId[79:64] = hdr.udp.dstPort;
        } else {
            // TotR
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

    bit<1>   mOpMode; 

    action encap_control (bit<32> countValue) {
        hdr.ethernet.etherType = TYPE_CTRL;
        hdr.ctrl.setValid();
        ROUTER_ID.read(hdr.ctrl.routerId, 0);
        hdr.ctrl.counterValue = countValue;
        hdr.ctrl.flag = 1;  
    }

    action s1Action () {
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
            meta.hhCounterCarried = mCountToWrite;
        }
    }

    action s2Action () {
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
            meta.hhCounterCarried = mCountToWrite;
        }
    }

    action countCheck () {
        bit<80> s1FlowId; bit<32> s1PktCount;
        bit<80> s2FlowId; bit<32> s2PktCount;
        s1FlowTracker.read(s1FlowId, meta.s1Index);
        s2FlowTracker.read(s2FlowId, meta.s2Index);
        s1PacketCount.read(s1PktCount, meta.s1Index);
        s1PacketCount.read(s2PktCount, meta.s2Index);

        // check table by table
        bit<80> fDiff;
        fDiff = meta.flowId - s1FlowId;
        if (fDiff == 0) {
            if (hdr.ctrl.counterValue > s2PktCount) {
                meta.hhDetected = 1;
            }
        } else {
            fDiff = meta.flowId - s2FlowId;
            if (fDiff == 0) {
                if (hdr.ctrl.counterValue > s2PktCount) {
                    meta.hhDetected = 1;
                }
            }
        }
    }

    action invalidateControlHeader() {
        hdr.ctrl.setInvalid();
    }

    action map_id_to_ip (ip4Addr_t routerIp) {
        meta.routerIp = routerIp;
    }

    table stage1 {
        key = {
            meta.mKeyCarried : exact;
            meta.mCountCarried : exact;
            meta.flowId : exact;
            meta.s1Index : exact;
            meta.s2Index : exact;
            meta.hhIndex : exact;
            meta.hhDiff : exact;
            meta.hhCounterCarried : exact;
        }
        actions = {
            s1Action();
        }
        default_action = s1Action();
    }

    table stage2 {
        key = {
            meta.mKeyCarried : exact;
            meta.mCountCarried : exact;
            meta.flowId : exact;
            meta.s1Index : exact;
            meta.s2Index: exact;
            meta.hhIndex : exact;
            meta.hhDiff : exact;
            meta.hhCounterCarried : exact;
        }
        actions = {
            s2Action();
        }
        default_action = s2Action();
    }

    table router_ip {
        key = {
            hdr.ctrl.routerId : exact;
        }
        actions = {
            map_id_to_ip;
            NoAction;
        }
        const entries = {
            (8w0x1) : map_id_to_ip(32w0x01010101);
            (8w0x2) : map_id_to_ip(32w0x02020202);
        }
        default_action = NoAction();
    }

    apply {
        // Extract flowId for processing
        extract_flow_id();
        compute_index();
        bool normal = false;
        if(meta.mOpMode == 0) {
            // Edge
            normal = true;
        } else {
            // TotR
            // Incoming notification message
            if(hdr.ctrl.isValid() && hdr.ctrl.flag == 1) {
                // valid header, and incoming notification message
                // check counter
                countCheck();

                if(meta.hhDetected == 1) {
                    // if malicious
                    // set flag to control
                    router_ip.apply();
                    hdr.ctrl.flag = 1;
                    ROUTER_ID.read(hdr.ctrl.routerId, 0);
                    // forward to where it came from
                    standard_metadata.egress_spec = standard_metadata.ingress_port;
                    hdr.ipv4.dstAddr = meta.routerIp;
                } else {
                    // if normal traffic, discard control header
                    invalidateControlHeader();
                }

            } else {
                // Normal packet
                // stage1.apply();
                // if (meta.mKeyCarried != 0 && meta.mCountCarried != 0)   stage2.apply();
                normal = true;
            }
        }

        if (normal) {
            stage1.apply();
            if (meta.mKeyCarried != 0 && meta.mCountCarried != 0)   stage2.apply();

            if(meta.mOpMode ==0){
                // If threshold exceeded, append notification header
                if(meta.hhCounterCarried !=0) {
                    encap_control(meta.hhCounterCarried);
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
        packet.emit(hdr.ctrl);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
