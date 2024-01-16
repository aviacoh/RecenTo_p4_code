/*
    RecenTo: A recent heavy-htter detection algorithm using Minimal Recirculation

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


//== Preamble: macro, header and parser definitions
#define INC 4
#define THRESHOLD_FIX 0xffe0 // 0xffff - 0x1f
#define FIX_ABR_COUNTER_VAL 0x80
#define MAX_ABR_COUNTER 0xffff

#define _OAT(act) table tb_## act {  \
            actions = {act;}                 \
            default_action = act();          \
            size = 1;               \
        }

#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

struct p_register_pair_t {
    bit<16> key;
    bit<16> place_counter;
}


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_h {
    bit<3>  pri;
    bit<1>  cfi;
    bit<12> vlan_id;
    bit<16> etherType;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;

    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    vlan_h vlan;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

header resubmit_data_64bit_t {
    //size is 64, same as port meta
    bit<32> fix_counter;
    bit<32> _padding;
}

header resubmit_data_skimmed_t {
    bit<32> fix_counter;
}


@pa_container_size("ingress","ig_md.key_part_1",16)
@pa_container_size("ingress","ig_md.key_part_2",16)
@pa_container_size("ingress","ig_md.key_part_3",16)
@pa_container_size("ingress","ig_md.key_part_4",16)
struct ig_metadata_t {
    resubmit_data_64bit_t resubmit_data_read;
    resubmit_data_skimmed_t resubmit_data_write;

    //64bit flowID
    bit<16> key_part_1;
    bit<16> key_part_2;
    bit<16> key_part_3;
    bit<16> key_part_4;

    //register index to access (hash of flow ID, with different hash functions)
    bit<16> stage_1_loc;
    bit<16> stage_2_loc;
    //hash seeds, different width
    bit<3> hash_seed_1;
    bit<5> hash_seed_2;

    //is partial key matched register entry?
    bit<16> p_key_matched_1_1;
    bit<16> p_key_matched_1_2;
    bit<16> p_key_matched_1_3;
    bit<16> p_key_matched_1_4;
    bit<16> p_key_matched_2_1;
    bit<16> p_key_matched_2_2;
    bit<16> p_key_matched_2_3;
    bit<16> p_key_matched_2_4;

    bool matched_at_stage_1;
    bool matched_at_stage_2;

    //fix information
    bit<32> fix_flow_counter;
    bit<16> fix_place_counter;

    //if so, we need to carry current count, and remember c_min/min_stage
    bit<32> counter_read_1;
    bit<32> counter_read_2;
    //bit<32> counter_incr;//you have a match, this is incremented value
    bit<32> c_min;
    bit<32> diff;
}
struct eg_metadata_t {
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.extract(ig_md.resubmit_data_read);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1
        transition accept;
    }
}
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN: parse_vlan;
            default : reject;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Resubmit() resubmit;

    apply {

        if (ig_intr_dprsr_md.resubmit_type == 1) {
            resubmit.emit(ig_md.resubmit_data_write);
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}


// == Start of control logic
control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
        }
        action nop() {
        }

        action route_to_64(){
            //route to CPU NIC. on model, it is veth250
            ig_intr_tm_md.ucast_egress_port=64;
        }

// == Calculate flow ID for the packet

        action copy_key_common_(){
            #define BYTE_1 0xff
            #define BYTE_2 0xff00

            bit<16> src_value_1 = hdr.ipv4.src_addr[15:0];
            bit<16> dst_value_1 = hdr.ipv4.dst_addr[15:0];
            bit<16> src_value_2 = hdr.ipv4.src_addr[31:16];
            bit<16> dst_value_2 = hdr.ipv4.dst_addr[31:16];

            ig_md.key_part_1=(src_value_1 & BYTE_1) | (dst_value_2 & BYTE_2);
            ig_md.key_part_2=(src_value_1 & BYTE_2) | (dst_value_2 & BYTE_1);
            ig_md.key_part_3=(src_value_2 & BYTE_1) | (dst_value_1 & BYTE_2);
            ig_md.key_part_4=(src_value_2 & BYTE_2) | (dst_value_1 & BYTE_1);
        }
        _OAT(copy_key_common_)

// == Calculate array indices for array access

        Hash<bit<16>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(16w0x8005,false,false,false,0,0)) hash1;
        Hash<bit<16>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(16w0x3D65,false,false,false,0,0)) hash2;

        action get_hashed_locations_1_(){
            ig_md.stage_1_loc=(bit<16>) hash1.get({
                ig_md.hash_seed_1,
                ig_md.key_part_1,
                3w0,
                ig_md.key_part_2,
                3w0,
                ig_md.key_part_3,
                ig_md.key_part_4
            });
        }
        action get_hashed_locations_2_(){
            ig_md.stage_2_loc=(bit<16>) hash2.get({
                ig_md.hash_seed_2,
                ig_md.key_part_1,
                2w0,
                ig_md.key_part_2,
                2w0,
                ig_md.key_part_3,
                1w0,
                ig_md.key_part_4
            });
        }
        _OAT(get_hashed_locations_1_)
        _OAT(get_hashed_locations_2_)


// == Register arrays for the stateful data structure

        Register<p_register_pair_t,_>(32w65536) p_register_1_1_R;
        Register<p_register_pair_t,_>(32w65536) p_register_1_2_R;
        Register<p_register_pair_t,_>(32w65536) p_register_1_3_R;
        Register<p_register_pair_t,_>(32w65536) p_register_1_4_R;
        Register<bit<32>,_>(32w65536) f_register_1_R;
        Register<p_register_pair_t,_>(32w65536) p_register_2_1_R;
        Register<p_register_pair_t,_>(32w65536) p_register_2_2_R;
        Register<p_register_pair_t,_>(32w65536) p_register_2_3_R;
        Register<p_register_pair_t,_>(32w65536) p_register_2_4_R;
        Register<bit<32>,_>(32w65536) f_register_2_R;


        // Define read/write actions for each flowID array
        #define RegAct_FlowID(st,pi) \
        RegisterAction<p_register_pair_t, _, bit<16>>(p_register_## st ##_## pi ##_R) stage_## st ##_p_reg_match_## pi ##_RA= {  \
            void apply(inout p_register_pair_t value, out bit<16> rv) {        \
                p_register_pair_t in_value;                                    \
                in_value = value;                                           \
                rv = in_value.place_counter;                                 \
                if(in_value.key==ig_md.key_part_## pi ){                \
                    /*Assume for this specification that counter value saturate
                        at his maximum value rather than wrapping around.*/\
                    value.place_counter=in_value.place_counter |+| INC;       \
                } else {                                                    \
                    if(in_value.place_counter==1){                           \
                        value.key=ig_md.key_part_## pi;                 \
                    } else {                                                \
                        value.place_counter=in_value.place_counter-1;         \
                        rv=0;                                               \
                    }                                                       \
                }                                                           \
            }                                                               \
        };                                                                  \
        action exec_stage_## st ##_p_reg_match_## pi ##_(){  ig_md.p_key_matched_## st ##_## pi=stage_## st ##_p_reg_match_## pi ##_RA.execute(ig_md.stage_## st ##_loc);}        \
        RegisterAction<p_register_pair_t, _, bit<16>>(p_register_## st ##_## pi ##_R) stage_## st ##_p_reg_decr_## pi ##_RA= {  \
            void apply(inout p_register_pair_t value, out bit<16> rv) {        \
                rv = 0;                                                     \
                p_register_pair_t in_value;                                    \
                in_value = value;                                           \
                if(in_value.place_counter>1){                                \
                    if(in_value.key==ig_md.key_part_## pi){             \
                        rv=1;                                               \
                    }                                                       \
                    value.place_counter=in_value.place_counter-1;             \
                }                                                           \
            }                                                               \
        };                                                                  \
        action exec_stage_## st ##_p_reg_decr_## pi ##_(){  ig_md.p_key_matched_## st ##_## pi=stage_## st ##_p_reg_decr_## pi ##_RA.execute(ig_md.stage_## st ##_loc);}  \
        RegisterAction<p_register_pair_t, _, bit<16>>(p_register_## st ##_## pi ##_R) stage_## st ##_p_reg_fix_## pi ##_RA= {  \
            void apply(inout p_register_pair_t value, out bit<16> rv) {        \
                rv = 0;                                                     \
                p_register_pair_t in_value;                                    \
                in_value = value;                                           \
                value.place_counter=FIX_ABR_COUNTER_VAL;                    \
            }                                                               \
        };                                                                  \
        action exec_stage_## st ##_p_reg_fix_## pi ##_(){  stage_## st ##_p_reg_fix_## pi ##_RA.execute(ig_md.stage_## st ##_loc);}                                             \
        RegisterAction<p_register_pair_t, _, bit<16>>(p_register_## st ##_## pi ##_R) stage_## st ##_p_reg_delete_## pi ##_RA= {  \
            void apply(inout p_register_pair_t value, out bit<16> rv) {        \
                rv = 0;                                                     \
                value.key=0;                                                \
                value.place_counter=1;                                       \
            }                                                               \
        };                                                                  \
        action exec_stage_## st ##_p_reg_delete_## pi ##_(){ stage_## st ##_p_reg_delete_## pi ##_RA.execute(ig_md.stage_## st ##_loc);}                                        \
        //done

        RegAct_FlowID(1,1)
        RegAct_FlowID(1,2)
        RegAct_FlowID(1,3)
        RegAct_FlowID(1,4)
        RegAct_FlowID(2,1)
        RegAct_FlowID(2,2)
        RegAct_FlowID(2,3)
        RegAct_FlowID(2,4)

        _OAT(exec_stage_1_p_reg_match_1_)
        _OAT(exec_stage_1_p_reg_fix_1_)

        _OAT(exec_stage_1_p_reg_match_2_)
        _OAT(exec_stage_1_p_reg_fix_2_)

        _OAT(exec_stage_1_p_reg_match_3_)
        _OAT(exec_stage_1_p_reg_fix_3_)

        _OAT(exec_stage_1_p_reg_match_4_)
        _OAT(exec_stage_1_p_reg_fix_4_)

        _OAT(exec_stage_2_p_reg_match_1_)
        _OAT(exec_stage_2_p_reg_decr_1_)
        _OAT(exec_stage_2_p_reg_delete_1_)

        _OAT(exec_stage_2_p_reg_match_2_)
        _OAT(exec_stage_2_p_reg_decr_2_)
        _OAT(exec_stage_2_p_reg_delete_2_)

        _OAT(exec_stage_2_p_reg_match_3_)
        _OAT(exec_stage_2_p_reg_decr_3_)
        _OAT(exec_stage_2_p_reg_delete_3_)

        _OAT(exec_stage_2_p_reg_match_4_)
        _OAT(exec_stage_2_p_reg_decr_4_)
        _OAT(exec_stage_2_p_reg_delete_4_)


        action set_matched_at_stage_1_(){
            ig_md.matched_at_stage_1=true;
        }
        action set_matched_at_stage_2_(){
            ig_md.matched_at_stage_2=true;
        }
        _OAT(set_matched_at_stage_1_)
        _OAT(set_matched_at_stage_2_)


        // Define stateful actions for matching flow ID
        #define RegAct_Counter(st) \
        RegisterAction<bit<32>, _, bit<32>>(f_register_## st  ##_R) stage_## st ##_counter_incr = {  \
            void apply(inout bit<32> value, out bit<32> rv) {         \
                rv = 0;                                               \
                bit<32> in_value;                                     \
                in_value = value;                                     \
                value = in_value |+| 1;                               \
                rv = value;                                           \
            }                                                         \
        };                                                            \
        action exec_stage_## st ##_counter_incr(){  ig_md.counter_read_## st =stage_## st ##_counter_incr.execute(ig_md.stage_## st ##_loc);} \
        RegisterAction<bit<32>, _, bit<32>>(f_register_## st  ##_R) stage_## st ##_counter_fix = {  \
            void apply(inout bit<32> value, out bit<32> rv) {           \
                rv = 0;                                                 \
                bit<32> in_value;                                       \
                in_value = value;                                       \
                value = in_value |+| ig_md.resubmit_data_read.fix_counter;  \
                rv = value;                                             \
            }                                                           \
        };                                                              \
        action exec_stage_## st ##_counter_fix(){  ig_md.counter_read_## st =stage_## st ##_counter_fix.execute(ig_md.stage_## st ##_loc);} \
        RegisterAction<bit<32>, _, bit<32>>(f_register_## st  ##_R) stage_## st ##_counter_write = {  \
            void apply(inout bit<32> value, out bit<32> rv) {           \
                rv = value;                                                 \
                value = 1;                                              \
            }                                                           \
        };                                                              \
        action exec_stage_## st ##_counter_write(){  ig_md.resubmit_data_write.fix_counter = stage_## st ##_counter_write.execute(ig_md.stage_## st ##_loc);} \
        //done

        RegAct_Counter(1)
        RegAct_Counter(2)
        _OAT(exec_stage_1_counter_incr)
        _OAT(exec_stage_1_counter_fix)
        _OAT(exec_stage_1_counter_write)
        _OAT(exec_stage_2_counter_incr)
        _OAT(exec_stage_2_counter_write)

        
        action clear_resubmit_flag(){
            ig_intr_dprsr_md.resubmit_type = 0;
        }
        action clone_and_recirc_replace_entry(){
            //trigger resubmit
            ig_intr_dprsr_md.resubmit_type = 1;
        }


        #undef _OAT
        #define _OAT(act) tb_##act.apply()
        apply {
            //for debugging
            route_to_64();

            // === Preprocessing ===
            // Get flow ID
            _OAT(copy_key_common_);

            // Get hashed locations based on flow ID
            _OAT(get_hashed_locations_1_);
            _OAT(get_hashed_locations_2_);

            // === Start of RecenTo stage counter logic ===

            // For normal packets, for each stage, we match flow ID, then increment or decrement place and flow counters
            // For resubmitted packet, just do write the relevant information at the right stage.

            bool is_resubmitted=(bool) ig_intr_md.resubmit_flag;

            // = Stage 1 match =

            if(!is_resubmitted){
                _OAT(exec_stage_1_p_reg_match_1_);
                _OAT(exec_stage_1_p_reg_match_2_);
                _OAT(exec_stage_1_p_reg_match_3_);
                _OAT(exec_stage_1_p_reg_match_4_);
            } else {
                _OAT(exec_stage_1_p_reg_fix_1_);
                _OAT(exec_stage_1_p_reg_fix_2_);
                _OAT(exec_stage_1_p_reg_fix_3_);
                _OAT(exec_stage_1_p_reg_fix_4_);
            }

            //have a boolean alias, for immediate use in gateway table controlling stage 2 fid match
            bool matched_at_stage_1=((ig_md.p_key_matched_1_1!=0) && 
               (ig_md.p_key_matched_1_2!=0) && 
               (ig_md.p_key_matched_1_3!=0) && 
               (ig_md.p_key_matched_1_4!=0));
            //also have a boolean phv value, for longer gateway matches
            if(matched_at_stage_1)
            {
                _OAT(set_matched_at_stage_1_);
            }

            bool replaced_at_stage_1=((ig_md.p_key_matched_1_1==1) || 
               (ig_md.p_key_matched_1_2==1) || 
               (ig_md.p_key_matched_1_3==1) || 
               (ig_md.p_key_matched_1_4==1));

            // = Stage 1 incr =

            if(!is_resubmitted){
                if(replaced_at_stage_1){
                    _OAT(exec_stage_1_counter_write);
                }else if(ig_md.matched_at_stage_1){
                    _OAT(exec_stage_1_counter_incr);
                }  
            }else{
                _OAT(exec_stage_1_counter_fix);
            }


            // = Stage 2 match =

            if(!is_resubmitted && !matched_at_stage_1){
                _OAT(exec_stage_2_p_reg_match_1_);
                _OAT(exec_stage_2_p_reg_match_2_);
                _OAT(exec_stage_2_p_reg_match_3_);
                _OAT(exec_stage_2_p_reg_match_4_);
            } else if(!is_resubmitted) {
                _OAT(exec_stage_2_p_reg_decr_1_);
                _OAT(exec_stage_2_p_reg_decr_2_);
                _OAT(exec_stage_2_p_reg_decr_3_);
                _OAT(exec_stage_2_p_reg_decr_4_);
            }else{
                _OAT(exec_stage_2_p_reg_delete_1_);
                _OAT(exec_stage_2_p_reg_delete_2_);
                _OAT(exec_stage_2_p_reg_delete_3_);
                _OAT(exec_stage_2_p_reg_delete_4_);
            }



             if((ig_md.p_key_matched_2_1!=0) &&
                (ig_md.p_key_matched_2_2!=0) &&
                (ig_md.p_key_matched_2_3!=0) &&
                (ig_md.p_key_matched_2_4!=0))
                {
                _OAT(set_matched_at_stage_2_);
                }
                

            bool replaced_or_duplicate_at_stage_2=((ig_md.p_key_matched_2_1==1) || 
               (ig_md.p_key_matched_2_2==1) || 
               (ig_md.p_key_matched_2_3==1) || 
               (ig_md.p_key_matched_2_4==1));

            // = Stage 2 incr =
            if(!is_resubmitted){
                if(replaced_or_duplicate_at_stage_2){
                    _OAT(exec_stage_2_counter_write);
                }else if(ig_md.matched_at_stage_2){
                    _OAT(exec_stage_2_counter_incr);
                }
            }

            clear_resubmit_flag();

            // === If fix needed, run recirculation (actually resubmit) ===
            if(!is_resubmitted && ig_md.matched_at_stage_1 && replaced_or_duplicate_at_stage_2){
                //none matched
                //prepare for resubmit!
                if(ig_md.resubmit_data_write.fix_counter & THRESHOLD_FIX != 0){
                    clone_and_recirc_replace_entry();
                }
            }
            else if(is_resubmitted){
                // finished second pipeline pass. route as normal.
            }
            else if(ig_md.matched_at_stage_1){
                // matched with counter.
            }else if(ig_md.matched_at_stage_2){
                // matched with counter.
            }


            if(ig_md.matched_at_stage_1){
                hdr.ethernet.dst_addr=(bit<48>)ig_md.counter_read_1;
            }else if(ig_md.matched_at_stage_2){
                hdr.ethernet.dst_addr=(bit<48>)ig_md.counter_read_2;
            }else{
                hdr.ethernet.dst_addr=1;
            }
        }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;

