#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 6;

const bit<32> NUM_SRC     = 256;
const bit<32> BLOOM_SIZE  = 65536;

const bit<32> SCAN_THRESHOLD = 20;
const bit<32> SCAN_HIGH      = 40;

const bit<8> MODE_OFF   = 0;
const bit<8> MODE_TOTAL = 1;
const bit<8> MODE_PROB  = 2;

const bit<8> PROB_LOW  = 50;
const bit<8> PROB_HIGH = 90;

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

struct metadata {
    bit<32> src_idx;
    bit<32> win;
    bit<32> last_win;
    bit<32> count;
    bit<32> h1;
    bit<32> h2;
    bit<32> tmp;
    bit<48> t0;
    bit<8>  anom;
    bit<8>  b1;
    bit<8>  b2;
    bit<8>  mode;
    bit<8>  do_drop;
    bit<8>  rnd;
    bit<8>  pct;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(NUM_SRC) reg_count;
    register<bit<32>>(NUM_SRC) reg_win;
    register<bit<8>>(NUM_SRC)  reg_anom;
    register<bit<48>>(NUM_SRC) reg_first_ts;
    register<bit<48>>(NUM_SRC) reg_detect_ts;
    register<bit<32>>(NUM_SRC) reg_passed;
    register<bit<32>>(NUM_SRC) reg_dropped;

    register<bit<8>>(BLOOM_SIZE) bloom1;
    register<bit<8>>(BLOOM_SIZE) bloom2;

    register<bit<8>>(1) reg_mode;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = 0x080000000000 | ((macAddr_t)port << 8);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            bit<48> ts = standard_metadata.ingress_global_timestamp;

            // Indice = 3o octeto do IP de origem (10.0.X.1 -> X). Sem colisao.
            meta.src_idx = (bit<32>)((hdr.ipv4.srcAddr >> 8) & 0xFF);
            meta.win = (bit<32>)(ts >> 20);

            reg_win.read(meta.last_win, meta.src_idx);
            reg_count.read(meta.count, meta.src_idx);

            if (meta.last_win != meta.win) {
                meta.anom = 0;
                if ((meta.last_win + 1 == meta.win) && (meta.count > SCAN_THRESHOLD)) {
                    meta.anom = 1;
                }
                reg_anom.write(meta.src_idx, meta.anom);
                reg_win.write(meta.src_idx, meta.win);
                meta.count = 0;
                reg_count.write(meta.src_idx, meta.count);
            } else {
                reg_anom.read(meta.anom, meta.src_idx);
            }

            if (hdr.tcp.isValid() && ((hdr.tcp.flags & 0x12) == 0x02)) {
                hash(meta.h1, HashAlgorithm.crc16, (bit<32>)0,
                     { hdr.ipv4.srcAddr, hdr.tcp.dstPort, meta.win }, BLOOM_SIZE);
                hash(meta.h2, HashAlgorithm.crc32, (bit<32>)0,
                     { hdr.ipv4.srcAddr, hdr.tcp.dstPort, meta.win }, BLOOM_SIZE);
                bloom1.read(meta.b1, meta.h1);
                bloom2.read(meta.b2, meta.h2);

                if (meta.b1 == 0 || meta.b2 == 0) {
                    bloom1.write(meta.h1, 1);
                    bloom2.write(meta.h2, 1);
                    meta.count = meta.count + 1;
                    reg_count.write(meta.src_idx, meta.count);

                    // first_ts / detect_ts: grava apenas a primeira vez
                    if (meta.count == 1) {
                        reg_first_ts.read(meta.t0, meta.src_idx);
                        if (meta.t0 == 0) {
                            reg_first_ts.write(meta.src_idx, ts);
                        }
                    }
                    if (meta.count == SCAN_THRESHOLD + 1) {
                        reg_detect_ts.read(meta.t0, meta.src_idx);
                        if (meta.t0 == 0) {
                            reg_detect_ts.write(meta.src_idx, ts);
                        }
                    }
                }
            }

            reg_mode.read(meta.mode, 0);
            meta.do_drop = 0;
            if (meta.mode != MODE_OFF &&
                (meta.anom == 1 || meta.count > SCAN_THRESHOLD)) {
                if (meta.mode == MODE_TOTAL) {
                    meta.do_drop = 1;
                } else {
                    meta.pct = PROB_LOW;
                    if (meta.count > SCAN_HIGH) {
                        meta.pct = PROB_HIGH;
                    }
                    random(meta.rnd, (bit<8>)0, (bit<8>)99);
                    if (meta.rnd < meta.pct) {
                        meta.do_drop = 1;
                    }
                }
            }

            if (meta.do_drop == 1) {
                reg_dropped.read(meta.tmp, meta.src_idx);
                reg_dropped.write(meta.src_idx, meta.tmp + 1);
                mark_to_drop(standard_metadata);
            } else {
                reg_passed.read(meta.tmp, meta.src_idx);
                reg_passed.write(meta.src_idx, meta.tmp + 1);
                ipv4_lpm.apply();
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
