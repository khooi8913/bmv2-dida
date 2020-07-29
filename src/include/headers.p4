/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_CTRL = 0x1234;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

enum bit<1> TrafficType {
    ATTACK = 0X01,
    NORMAL = 0X00
}

enum bit<1> DeviceType {
    ACCESS = 0x01,
    BORDER = 0x00
}

enum bit<8> ControlMessageType {
    NOTIFICATION = 0x00,
    CONTROL = 0x01
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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

// header ctrl_t {
//     bit<8>              routerId;
//     ControlMessageType  flag;   // 1 means notification, 0 means control
//     bit<32>             counterValue;
// }

// Control Header
header ctrl_t {
    bit<32>             source_rtr_id;
    bit<16>             flag;
    bit<32>             counter_val;
    bit<32>             tstamp_val;
}

struct metadata {
    DeviceType  mOpMode;
    TrafficType blDetected;
    bit<1>      suspicious;

    bit<32>     blDiff;
    bit<32>     routerIp;
    bit<8>      routerId;

    ip4Addr_t   srcIp;
    ip4Addr_t   dstIp;
    bit<16>     srcPort;
    bit<16>     dstPort;

    bit<32> suspicious_threshold;
    bit<32> attack_threshold;

    // CMS
    bit<32> sketch_min;

    bit<32> index_sketch0;
    bit<32> index_sketch1;
    bit<32> index_sketch2;
    bit<32> index_sketch3;
    bit<32> index_sketch4;
    bit<32> index_sketch5;

    bit<32> value_sketch0;
    bit<32> value_sketch1;
    bit<32> value_sketch2;
    bit<32> value_sketch3;
    bit<32> value_sketch4;
    bit<32> value_sketch5;

    bit<32>     window_sketch0;
    bit<32>     window_sketch1;
    bit<32>     window_sketch2;

    // BL
    bit<1>      addedToBl;
    bit<32>     index_bl0;
    bit<32>     index_bl1;
    bit<32>     index_bl2;
    bit<32>     index_bl3;

    bit<32>     value_bl0;
    bit<32>     value_bl1;
    bit<32>     value_bl2;
    bit<32>     value_bl3;

    bit<104>    flowId;
    bit<32>     mAbsWindowId;

    // new
    bit<32>     current_tstamp;
    bit<1>      is_response;
    bit<1>      is_ctrl;
    bit<1>      is_request;
    bit<1>      is_suspicious;
    bit<1>      is_attack;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t       udp;
    ctrl_t      ctrl;
}
