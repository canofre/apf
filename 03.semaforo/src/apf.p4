/* -*- APF - ANALISADOR PRELIMITAR DE FLUXO -*- */
#include <core.p4>
#include <v1model.p4>

/* Tipo de pacote - standard_metadata.instance_type */
#define PKT_NORMAL 0x0
#define PKT_CLONE_I2I 0x1
#define PKT_CLONE_E2I 0x2
#define PKT_CLONE_I2E 0x8
#define PKT_CLONE_E2E 0x9
#define PKT_RECIRCULADO 0x3

/* Divisor para controle de overflow */
#define DIVISOR 11    // 2048

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_UDP = 0x11;

typedef bit<32> var32_t;
typedef bit<48> var48_t; 
typedef bit<64> var64_t;

register<var32_t>(4) reg32;

/*********************************************************
*************** H E A D E R S  ***************************
*********************************************************/
header ethernet_t {
  var48_t macDst;
  var48_t macSrc;
  bit<16>   etherType; 
}

header ipv4_t {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  diffserv;
  bit<16> totalLen;
  bit<16> identification;
  bit<3>  flags;
  bit<13> fragOffset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> hdrChecksum;
  var32_t srcAddr;
  var32_t dstAddr;
}

header udp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<16> lengthUdp;
  bit<16> checksum;
}

header apf_t{
  var32_t v1;
  var32_t v2;
  var32_t v3;
  var32_t v4;
  bit<2> analisar;
}

header intrinsic_metadata_t {
  var64_t ingress_global_tstamp;
  var64_t current_global_tstamp;
  var32_t janela;   // tam janela
  var32_t peso_mj;  // 1-lambda
  var32_t peso_mh;  // lambda
}

struct metadata {
  intrinsic_metadata_t intrinsic_metadata;
}

struct headers {
  ethernet_t  ethernet;  
  ipv4_t      ipv4;   
  udp_t       udp;   
  apf_t       apf;  
}

/*********************************************************
*************** P A R S E R  *****************************
*********************************************************/
parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t smt) {

  state start {
    transition parse_ethernet;
  }

  state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType){
      TYPE_IPV4: parse_ipv4;
      default: accept; 
    }
  }
  
  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition parse_apf;
  }
  
  state parse_apf {
    packet.extract(hdr.apf);
    transition select(hdr.ipv4.protocol){
      PROTO_UDP: parse_udp;
      default: accept;
    }
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition accept;
  }
}

/*********************************************************
******   C H E C K S U M  V E R I F I C A T I O N   ******
**********************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
  apply {  }
}

/*********************************************************
******  I N G R E S S   P R O C E S S I N G **************
*********************************************************/
control MyIngress(inout headers hdr, 
          inout metadata meta, 
          inout standard_metadata_t smt) {
  action drop() {
    mark_to_drop();
  }
  
  action ipv4_forward(var48_t macDst, bit<16> port) {
    smt.egress_spec = port;
    hdr.ethernet.macSrc = hdr.ethernet.macDst;
    hdr.ethernet.macDst = macDst;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  }
  
  table tb_ipv4 {
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
  
  /* Inicializar as metricas a serem utilizadas no computo da medias */   
  action metricas_get(var32_t janela, var32_t peso_mh, var32_t peso_mj){
    meta.intrinsic_metadata.janela = janela;
    meta.intrinsic_metadata.peso_mh = peso_mh;
    meta.intrinsic_metadata.peso_mj = peso_mj;
    hdr.apf.analisar = 0;
  }
  
  table tb_metricas {
    actions = {
      metricas_get;
      NoAction;
    }
    default_action = NoAction();
  }

  /* Alterar a porta de saida para interface v0_3 = 771 */ 
  action monitor_send(bit<16> porta){
    smt.egress_spec = porta;
    hdr.ipv4.diffserv = 0xC8;
  }

  table tb_monitor {
    actions = {
      monitor_send;
      NoAction;
    }
    default_action = NoAction();
  }
   
  /* 
  * Pacote valido e clonado, aplica a mudanca de porta para enviar
  * ao coletor, caso contrario aplica o encaminhamento padrao
  */
  apply {
    if ( hdr.ipv4.isValid() ){
      if ( smt.instance_type ==  PKT_CLONE_E2I ){
        tb_monitor.apply();
      } else {
        tb_ipv4.apply();   
        tb_metricas.apply();
      }
    }
  }
}

/* Importacao do micro-c */
extern void analisaPacote();
/*********************************************************
******  E G R E S S   P R O C E S S I N G   **************
*********************************************************/
control MyEgress(inout headers hdr, 
         inout metadata meta, 
         inout standard_metadata_t smt) {

  /* 
  * Necessita de uma declaracao inicial externamente a action para 
  * recuperar o current_timestamp 
  */
  var64_t ct64 = meta.intrinsic_metadata.current_global_tstamp;
  var64_t it64 = meta.intrinsic_metadata.ingress_global_tstamp;
  var64_t df64 = ct64-it64; 
  
  /* 
  * Calcula as metricas a serem utilizadas na avaliacao do pacote
  * armazenando no cabecalho temporario do pacote
  */
  action metricas_get(){
    hdr.apf.v1  = ct64[31:0]-it64[31:0];
    hdr.apf.v2 = (var32_t)smt.packet_length;
    hdr.apf.v3 = 0;
    hdr.apf.v4 = 0;
  }

  /* Registra parciais dos valores de execucao */
  action writeReg(){
    ct64 = meta.intrinsic_metadata.current_global_tstamp;
    hdr.apf.v4=(ct64[31:0]-it64[31:0]) >> DIVISOR;
    reg32.write(0,hdr.apf.v1); // pacotes
    reg32.write(1,hdr.apf.v2); // clonados
    reg32.write(2,hdr.apf.v3); // mph 
    reg32.write(3,hdr.apf.v4); // latencia
  }

  apply {
    if( smt.instance_type == PKT_NORMAL && hdr.ipv4.isValid() ){
      metricas_get();

      analisaPacote();

      /* Clona os pacotes que excederem os parametros definidos */
      if (hdr.apf.analisar == 1 ){
        clone(CloneType.E2I,1);
      }else{
        /* Invalida o cabecalho dos pacotes nao clonados */
        hdr.apf.setInvalid();
      }

      writeReg();

    }else{
      /* Invalida o cabecalho dos pacotes clonados */
      hdr.apf.setInvalid();
    }
  }
}

/*********************************************************
*******   C H E C K S U M  C O M P U T A T I O N   *******
*********************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta){
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

/*********************************************************
************  D E P A R S E R  ***************************
*********************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.udp);
    packet.emit(hdr.apf);
  }
}

/*********************************************************
***************  S W I T C H  ****************************
*********************************************************/
V1Switch( 
  MyParser(), 
  MyVerifyChecksum(), 
  MyIngress(), 
  MyEgress(), 
  MyComputeChecksum(), 
  MyDeparser()
) main;