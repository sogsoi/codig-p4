// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  ICMP_ECHO_REQUEST = 8;
const bit<8>  ICMP_ECHO_REPLY   = 0;

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
const bit<16> ICMP_PAYLOAD_BYTES = 48;
const bit<16> ICMP_PAYLOAD_BITS  = 384;

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence;
}

header icmp_payload_t {
    bit<384> data;
}

struct metadata {
    bool is_for_me;
    bit<16> icmp_payload_len; 
}

struct headers {
    ethernet_t     ethernet;
    ipv4_t         ipv4;
    icmp_t         icmp;
    icmp_payload_t icmp_payload;
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
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition select(hdr.icmp.type) {
            ICMP_ECHO_REQUEST: parse_icmp_payload;
            default: accept;
        }
    }

    state parse_icmp_payload {
        packet.extract(hdr.icmp_payload);
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

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
    action mark_for_me() {
        meta.is_for_me = true;
    }

    table my_addresses {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            mark_for_me;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }
    action send_echo_reply() {
        macAddr_t tmpMac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmpMac;
        ip4Addr_t tmpIp = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmpIp;
        hdr.ipv4.ttl = 64;
        hdr.icmp.type = ICMP_ECHO_REPLY;
        hdr.icmp.code = 0;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        meta.is_for_me = false;
        if (hdr.ipv4.isValid()) {
            my_addresses.apply();
        }

        if (meta.is_for_me &&
            hdr.icmp.isValid() &&
            hdr.icmp_payload.isValid() &&
            hdr.icmp.type == ICMP_ECHO_REQUEST &&
            hdr.icmp.code == 0) {
            send_echo_reply();
        } else if (meta.is_for_me) {
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

        update_checksum(
            hdr.icmp.isValid(),
            { hdr.icmp.type,
              hdr.icmp.code,
              hdr.icmp.identifier,
              hdr.icmp.sequence,
              hdr.icmp_payload.data },
            hdr.icmp.checksum,
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
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmp_payload);
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

