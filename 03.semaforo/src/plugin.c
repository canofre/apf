/*
* Modulo externo com a utilizacao de semaforo vetorizado
* para controle de concorrencia nas as ilhas de FPCs.
*/
#include <nfp.h>
#include <stdint.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include "pif_plugin.h"

/*Pesos para media_ponderada 2^16*/
#define PESO_TSTAMP 45875   //  0.7
#define PESO_PKTLEN 19660   //  0.3
#define SC_UP 16

/* Divisor para controle de overflow */
#define DIVISOR 11       // 2048


/* Variaveis para registro */
__declspec(emem shared scope(global) export) uint32_t pacotes; 
__declspec(emem shared scope(global) export) uint32_t clonados;

/* Variaveis ativas */
__declspec(emem shared scope(global) export) uint32_t janela[HASH_MAX+1];
__declspec(emem shared scope(global) export) uint32_t mp_acumulada[HASH_MAX+1];
__declspec(emem shared scope(global) export) uint32_t mp_historica[HASH_MAX+1];

/*  Inicializada em plugin_init_master */
__declspec(emem export aligned(64)) int global_semaforos[HASH_MAX+1];

/* Hash para obtencao do index do semaforo */
int getHash(uint32_t ip1, uint32_t ip2){
  uint32_t hash_key[2];
  uint32_t hash_id;
  hash_key[0] = ip1;
  hash_key[1] = ip2;
  hash_id = hash_me_crc32((void *)hash_key,sizeof(hash_key), 1);
  hash_id &= HASH_MAX; 
  return (int)hash_id;
}

void semaforo_down(volatile __declspec(mem addr40) void * addr) {
  /* semaforo "DOWN" = claim = wait */
  unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
  SIGNAL_PAIR my_signal_pair;

  addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
  addr_lo = (unsigned long long int)addr & 0xffffffff;
  
  do {
     xfer = 1;
     __asm {
       mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1], \
         sig_done[my_signal_pair];
       ctx_arb[my_signal_pair]
     }
   } while (xfer == 0);
}

void semaforo_up(volatile __declspec(mem addr40) void * addr) {
  /* semaforo "UP" = release = signal */
  unsigned int addr_hi, addr_lo;
  __declspec(read_write_reg) int xfer;
  addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
  addr_lo = (unsigned long long int)addr & 0xffffffff;

  __asm {
    mem[incr, --, addr_hi, <<8, addr_lo, 1];
  }
}

/* 
* Chamada uma vez para todo sistema. Necessario habilitar 
* opcao para compliacao via linha de comando 
*/
void pif_plugin_init_master() {
  int i;
  for (i = 0; i < HASH_MAX+1; i++) {
    global_semaforos[i]=1;
    semaforo_up(&global_semaforos[i]);
  }
}

/* chamado uma vez para cada thread */
void pif_plugin_init() { }

int pif_plugin_analisaPacote(EXTRACTED_HEADERS_T *hdr, MATCH_DATA_T *meta){
  
  PIF_PLUGIN_apf_T *apf = pif_plugin_hdr_get_apf(hdr);
  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(hdr);

  __xwrite uint32_t xw = 0;
  __xread uint32_t xr_mpa;
  __xread uint32_t xr_mh;
  __xread uint32_t xr_janela;
  uint32_t hash_id = 0;
  uint32_t mp = 0;
  int i=0; 
  mem_incr32((__mem40 void*)&pacotes);
  
  hash_id = getHash(ipv4->srcAddr,ipv4->dstAddr);
  semaforo_down(&global_semaforos[hash_id]);
   
  /* Calcula media ponderada */
  xw = mp = ((((uint64_t)PESO_TSTAMP*(uint64_t)apf->v1) / 
  (1 << SC_UP)) + ((PESO_PKTLEN*apf->v2) / 1 << SC_UP))) >> DIVISOR;
  
  /* Incrementa janela: fora do mutex nao conta corretamente */
  mem_incr32((__mem40 void*)&janela[hash_id]);
  /* Recupera janela atual */
  mem_read_atomic(&xr_janela,(__mem40 void*)&janela[hash_id],sizeof(xr_janela));

  /* Incrementa media acumulada */
  mem_add32(&xw,(__mem40 void*)&mp_acumulada[hash_id],sizeof(xw));

  /* Recupera a media historica */
  mem_read_atomic(&xr_mh,(__mem40 void*)&mp_historica[hash_id],sizeof(xr_mh));

  /* Compara media pacote com media historica e tamanho da janela */
  if ( mp > xr_mh && xr_mh != 0 ){
    apf->analisar=1;
    mem_incr32((__mem40 void*)&clonados);
  }

  /* Recalcula a media historica */
  if ( xr_janela == PKT_JANELA ){
    /* Reseta contador da janela */
    xw=0;
    mem_write_atomic(&xw,(__mem40 void*)&janela[hash_id],sizeof(xw));
  
    /* Recupera media acumulada e reseta */
    mem_read_atomic(&xr_mpa,(__mem40 void*)&mp_acumulada[hash_id],sizeof(xr_mpa));
    mem_write_atomic(&xw,(__mem40 void*)&mp_acumulada[hash_id],sizeof(xw));

    /* Calcula a nova media  historica - calculo 1 */
    if (xr_mh != 0 ){
      xw = ((xr_mpa / PKT_JANELA) * PESO_MJ) / (1 << SC_UP) +
        (PESO_MH * xr_mh) / (1 << SC_UP); 
    }else{
      /*  A primeira media e a media ponderada simples */
      xw = (xr_mpa / PKT_JANELA );
    }

    mem_write_atomic(&xw,(__mem40 void*)&mp_historica[hash_id],sizeof(xw));
  }

  semaforo_up(&global_semaforos[hash_id]);
  apf->v1 = pacotes;
  apf->v2 = clonados;
  mem_read_atomic(&xr_mh,(__mem40 void*)&mp_historica[hash_id],sizeof(xr_mh));
  apf->v3 = xr_mh;
  
  return PIF_PLUGIN_RETURN_FORWARD;
}

/*
* Marca todos os pacotes para serem clonados. A realizacao deste 
* processo com o micro-c facilita a contagem de pacotes
* por intervalo e assim o monitoramento do desempemho
*/
int pif_plugin_intClassico(EXTRACTED_HEADERS_T *hdr, MATCH_DATA_T *meta){
  
  PIF_PLUGIN_apf_T *apf = pif_plugin_hdr_get_apf(hdr);
  uint32_t mp = 0;
  
  mem_incr32((__mem40 void*)&pacotes);
  apf->analisar=1;
  
  apf->v1 = apf->v2 =  pacotes; 
  
  return PIF_PLUGIN_RETURN_FORWARD;
}