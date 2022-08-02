/*
* Modulo externo com a utilizacao de mutex para controle de
* concorrencia, utilizando apenas uma das ilhas de FPCs.
*/
#include <nfp.h>
#include <mutexlv.h>
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_plugin.h>

/* Pesos para media_ponderada 2^16*/
#define PESO_TSTAMP 45875   // 0.7
#define PESO_PKTLEN 19660   //  0.3
#define SC_UP 16

/* Media calculada pela distribuicao de pacotes por intervalo */
#define MEDIA_FIXA 142
/* Divisor para controle de overflow */
#define DIVISOR 11       // 2048

/* Variaveis para registro */
__declspec(emem shared scope(global) export) uint32_t pacotes; 
__declspec(emem shared scope(global) export) uint32_t clonados;

/* Variaveis ativas */
__declspec(emem shared scope(global) export) uint32_t janela;
__declspec(emem shared scope(global) export) uint32_t mp_acumulada;
__declspec(emem shared scope(global) export) uint32_t mp_historica=0;

/* Mutex */
typedef volatile __shared __gpr unsigned int MUTEXLV;
MUTEXLV lock=0;

int pif_plugin_analisaPacote(EXTRACTED_HEADERS_T *hdr, MATCH_DATA_T *meta){
  
  PIF_PLUGIN_apf_T *apf = pif_plugin_hdr_get_apf(hdr);
  
  __xwrite uint32_t xw = 0;
  __xread uint32_t xr_mpa;
  __xread uint32_t xr_mh;
  __xread uint32_t xr_janela;
  uint32_t mp = 0;

  mem_incr32((__mem40 void*)&pacotes);
  
  MUTEXLV_lock(lock,1);
   
  /* Calcula media ponderada */
  xw = mp = ((((uint64_t)PESO_TSTAMP*(uint64_t)apf->v1) / 
  (1 << SC_UP)) + ((PESO_PKTLEN*apf->v2) / 1 << SC_UP))) >> DIVISOR;
  
  /* Incrementa janela: fora do mutex nao conta corretamente */
  mem_incr32((__mem40 void*)&janela);
  /* Recupera janela atual */
  mem_read_atomic(&xr_janela,(__mem40 void*)&janela,sizeof(xr_janela));

  /* Incrementa media acumulada */
  mem_add32(&xw,(__mem40 void*)&mp_acumulada,sizeof(xw));

  /* Recupera a media historica */
  mem_read_atomic(&xr_mh,(__mem40 void*)&mp_historica,sizeof(xr_mh));

  /* Compara media pacote com media historica e tamanho da janela */
  if ( mp > xr_mh && xr_mh != 0 ){
    apf->analisar=1;
    mem_incr32((__mem40 void*)&clonados);
  }

  /* Recalcula a media historica */
  if ( xr_janela == PKT_JANELA ){
    /* Reseta contador da janela */
    xw=0;
    mem_write_atomic(&xw,(__mem40 void*)&janela,sizeof(xw));
  
    /* Recupera media acumulada e reseta */
    mem_read_atomic(&xr_mpa,(__mem40 void*)&mp_acumulada,sizeof(xr_mpa));
    mem_write_atomic(&xw,(__mem40 void*)&mp_acumulada,sizeof(xw));

    /* Calcula a nova media  historica - calculo 1 */
    if (xr_mh != 0 ){
      xw = ((xr_mpa / PKT_JANELA) * PESO_MJ) / (1 << SC_UP) +
        (PESO_MH * xr_mh) / (1 << SC_UP); 
    }else{
      /*  A primeira media  a media ponderada simples */
      xw = (xr_mpa / PKT_JANELA );
    }

    mem_write_atomic(&xw,(__mem40 void*)&mp_historica,sizeof(xw));
  }
    
  MUTEXLV_unlock(lock,1);
  apf->v1 = pacotes;
  apf->v2 = clonados; 
  /* Recupera a media ponderada historica para registro */
  mem_read_atomic(&xr_mh,(__mem40 void*)&mp_historica,sizeof(xr_mh));
  apf->v3 = xr_mh; 

  return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_analisaPacoteEstatico(EXTRACTED_HEADERS_T *hdr, MATCH_DATA_T *meta){
  
  PIF_PLUGIN_apf_T *apf = pif_plugin_hdr_get_apf(hdr);
  uint32_t mp = 0;
  
  mem_incr32((__mem40 void*)&pacotes);
  
  MUTEXLV_lock(lock,1);
  
  /* Calcula media ponderada */
  mp = ((((uint64_t)PESO_TSTAMP*(uint64_t)apf->v1) / (1 << SC_UP)) +
      ((PESO_PKTLEN*apf->v2) / (1 << SC_UP))) >> DIVISOR ;
   
  /* Compara media pacote com media historica e tamanho da janela */
  if ( mp > MEDIA_FIXA ){
    mem_incr32((__mem40 void*)&clonados);
    apf->analisar=1;
  }

  MUTEXLV_unlock(lock,1);
  apf->v1 = pacotes; 
  apf->v2 = clonados;
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