// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 6;
const bit<8>  PROTO_UDP = 17;

const bit<32> PUBLIC_IP   = 0xC8000001;
const bit<9>  EXT_PORT    = 3;
const bit<16> ALLOC_START = 20000;

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

struct metadata {
    bit<16> l4_src;
    bit<16> l4_dst;
    bit<16> st_ext_port;
    bit<32> st_ip;
    bit<16> st_port;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
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
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

bit<16> csum_update(in bit<16> c,
                    in bit<32> oldIp, in bit<32> newIp,
                    in bit<16> oldPort, in bit<16> newPort) {
    bit<32> sum = 0;
    sum = sum + (bit<32>)(~c);
    sum = sum + (bit<32>)(~oldIp[31:16]);
    sum = sum + (bit<32>)(~oldIp[15:0]);
    sum = sum + (bit<32>)(newIp[31:16]);
    sum = sum + (bit<32>)(newIp[15:0]);
    sum = sum + (bit<32>)(~oldPort);
    sum = sum + (bit<32>)(newPort);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    bit<16> r = (bit<16>)sum;
    return ~r;
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(131072) rev_ip;
    register<bit<16>>(131072) rev_port;
    register<bit<16>>(65536)  fwd_port;
    register<bit<16>>(1)      next_port;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        default_action = drop();
    }

    action set_dnat(bit<32> ip, bit<16> port) {
        meta.st_ip   = ip;
        meta.st_port = port;
    }

    table dnat_static {
        key = {
            hdr.ipv4.protocol: exact;
            meta.l4_dst:       exact;
        }
        actions = { set_dnat; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    action set_snat(bit<16> ext_port) {
        meta.st_ext_port = ext_port;
    }

    table snat_static {
        key = {
            hdr.ipv4.protocol: exact;
            hdr.ipv4.srcAddr:  exact;
            meta.l4_src:       exact;
        }
        actions = { set_snat; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    apply {
        if (!hdr.ipv4.isValid() || hdr.ipv4.ihl != 5 ||
            (!hdr.tcp.isValid() && !hdr.udp.isValid()) ||
            hdr.ipv4.ttl <= 1) {
            drop();
            return;
        }

        bit<32> pbase = 0;
        if (hdr.tcp.isValid()) {
            meta.l4_src = hdr.tcp.srcPort;
            meta.l4_dst = hdr.tcp.dstPort;
        } else {
            meta.l4_src = hdr.udp.srcPort;
            meta.l4_dst = hdr.udp.dstPort;
            pbase = 65536;
        }

        bool ok = true;
        bit<32> oldIp;
        bit<16> oldPort;
        bit<32> newIp;
        bit<16> newPort;

        if (standard_metadata.ingress_port != EXT_PORT) {
            oldIp   = hdr.ipv4.srcAddr;
            oldPort = meta.l4_src;
            newIp   = PUBLIC_IP;
            newPort = meta.l4_src;

            meta.st_ext_port = 0;
            snat_static.apply();

            if (meta.st_ext_port != 0) {
                newPort = meta.st_ext_port;
            } else {
                bit<32> rip0;
                bit<16> rport0;
                bit<32> idx0 = pbase + (bit<32>)meta.l4_src;
                rev_ip.read(rip0, idx0);
                rev_port.read(rport0, idx0);

                bit<16> h;
                hash(h, HashAlgorithm.crc16, (bit<16>)0,
                     { hdr.ipv4.srcAddr, meta.l4_src, hdr.ipv4.protocol },
                     (bit<32>)65536);

                if (rip0 == hdr.ipv4.srcAddr && rport0 == meta.l4_src) {
                    newPort = meta.l4_src;
                } else {
                    bit<16> cand;
                    bit<32> rip1;
                    bit<16> rport1;
                    fwd_port.read(cand, (bit<32>)h);
                    rev_ip.read(rip1, pbase + (bit<32>)cand);
                    rev_port.read(rport1, pbase + (bit<32>)cand);

                    if (cand != 0 && rip1 == hdr.ipv4.srcAddr && rport1 == meta.l4_src) {
                        newPort = cand;
                    } else if (rip0 == 0) {
                        rev_ip.write(idx0, hdr.ipv4.srcAddr);
                        rev_port.write(idx0, meta.l4_src);
                        newPort = meta.l4_src;
                    } else {
                        bit<16> np;
                        next_port.read(np, 0);
                        if (np < ALLOC_START) {
                            np = ALLOC_START;
                        }
                        bit<32> idx1 = pbase + (bit<32>)np;
                        bit<32> rip2;
                        rev_ip.read(rip2, idx1);
                        if (rip2 != 0) {
                            ok = false;
                        } else {
                            rev_ip.write(idx1, hdr.ipv4.srcAddr);
                            rev_port.write(idx1, meta.l4_src);
                            fwd_port.write((bit<32>)h, np);
                            next_port.write(0, np + 1);
                            newPort = np;
                        }
                    }
                }
            }

            if (ok) {
                hdr.ipv4.srcAddr = newIp;
                if (hdr.tcp.isValid()) {
                    hdr.tcp.srcPort  = newPort;
                    hdr.tcp.checksum = csum_update(hdr.tcp.checksum, oldIp, newIp, oldPort, newPort);
                } else {
                    hdr.udp.srcPort = newPort;
                    if (hdr.udp.checksum != 0) {
                        bit<16> c = csum_update(hdr.udp.checksum, oldIp, newIp, oldPort, newPort);
                        if (c == 0) { c = 0xFFFF; }
                        hdr.udp.checksum = c;
                    }
                }
            }
        } else {
            if (hdr.ipv4.dstAddr != PUBLIC_IP) {
                ok = false;
            } else {
                oldIp   = hdr.ipv4.dstAddr;
                oldPort = meta.l4_dst;
                newIp   = 0;
                newPort = 0;

                meta.st_ip = 0;
                dnat_static.apply();

                if (meta.st_ip != 0) {
                    newIp   = meta.st_ip;
                    newPort = meta.st_port;
                } else {
                    bit<32> rip;
                    bit<16> rport;
                    bit<32> idx = pbase + (bit<32>)meta.l4_dst;
                    rev_ip.read(rip, idx);
                    rev_port.read(rport, idx);
                    if (rip == 0) {
                        ok = false;
                    } else {
                        newIp   = rip;
                        newPort = rport;
                    }
                }

                if (ok) {
                    hdr.ipv4.dstAddr = newIp;
                    if (hdr.tcp.isValid()) {
                        hdr.tcp.dstPort  = newPort;
                        hdr.tcp.checksum = csum_update(hdr.tcp.checksum, oldIp, newIp, oldPort, newPort);
                    } else {
                        hdr.udp.dstPort = newPort;
                        if (hdr.udp.checksum != 0) {
                            bit<16> c2 = csum_update(hdr.udp.checksum, oldIp, newIp, oldPort, newPort);
                            if (c2 == 0) { c2 = 0xFFFF; }
                            hdr.udp.checksum = c2;
                        }
                    }
                }
            }
        }

        if (!ok) {
            drop();
        } else {
            ipv4_lpm.apply();
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
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
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
