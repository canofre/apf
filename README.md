# APF - Analisador Preliminar de Fluxo

Realiza a classificação dos pacotes a serem encaminhados para o coletor. Utiliza as métricas disponíveis de forma ponderada e compara com uma média histórica para classificar os pacotes.

São também realizadas medições de latência em nanossegundos, através da diferença dos *timestamp* de saída e entrada. 

## Organização

Os códigos e resultados estão separados em três grupos:

- **01.fluxo_basico**: execuções realizadas com um modelo de encaminhamento básico de pacotes, utilizada para comparação de sobrecarga e desempenho, não sendo realizados processamentos adicionais. Os resultados são apresentados separados em:
  - mono-ilha: com limitação de 1 ilha de processamento e 5 FPCs nesta ilha;
  - multi-ilha: com a utilização das 5 ilhas e das 12 FPCs de cada ilha.
- **02.mutex**: execuções realizadas utilizando a biblioteca mutex da Netronome para controle de concorrência e com limitação de processamento, utilizando apenas 1 ilha de FPCs e 5 FPCs das 12 presentes na ilha. Os resultados são apresentados separados em: *int_classico*, *variacao_janela* e *variacao_lambda*; 
- **03.semaforo**: execuções realizadas utilizando uma implementação de semáforo vetorial para controle de concorrência, sem limitação de processamento, utilizando as 5 ilha de FPCs e as 12 FPCs de casa ilha. Os resultados são apresentados separados em: *int_classico* e *variacao_janela*.

A execução da abordagem dinâmica, estática ou clássica se dá pela importação da função definida em no arquivo plugin.c que vai ser chamada no arquivo P4.

- ```extern void analisaPacote();``` : realiza a análise dinâmica;
- ```extern void analisaPacoteEstático();``` : realiza a análise estática com média fixa;
- ```extern void intClassico();``` : implementa a abordagem clássica clonando todos os pacotes;

## Compilação

Para realizar a compilação via linha de comando no linux foi utilizada a linha a seguir:

```
 /opt/netronome/p4/bin/nfp4build --output-nffw-filename driver.nffw -4 $1 \
    --sku nfp-4xxx-b0 --platform hydrogen --reduced-thread-usage \
    --no-shared-codestore --debug-info --nfp4c_p4_version 16 \
    --nfp4c_p4_compiler p4c-nfp --nfirc_default_table_size 65536 \
    --nfirc_no_all_header_ops --nfirc_implicit_header_valid \
    --nfirc_no_zero_new_headers --nfirc_multicast_group_count 16 \
    --nfirc_multicast_group_size 16 --nfirc_mac_ingress_timestamp \
    --disable-component flowcache [OPÇÕES] > nfp4build.log
```

- **opções:**
  - ```-A 5 -u 1``` : limita a quantidade de FPCs e ilhas para 5 e 1 respectivamente;
  - ```-DPIF_PLUGIN_INIT```: inicializa e permite o uso das chamadas de sistema  ```pif_plugin_init_master() { ... }``` e ``` pif_plugin_init() { }```
  - ```plugin="-c plugin.c``` : compila com um plugin micro-c;
 
 Para carregar o *driver* foi utilizado o comando a seguir, que pode ser utilizado sem repassar o arquivo de configuração. Neste caso do *driver* é carregado mas sem nenhuma tabela para uso.

 ```
  /opt/netronome/p4/bin/rtecli -p 20206 design-load -f driver.nffw -c arqConf.p4cfg
 ```

## Execução

A execução do MoonGen foi realizada a partir de dois comandos, um para o host gerador do fluxo constante e outro para o host gerador de rajadas de fluxo, realizando os ajustes de IP necessários. As opções utilizadas indicam:

- **tx/rx**: as portas de origem e destino;
- **--src-ip/--dst-ip**: os IPs de origem e destino;
- **-sipv/-dipv**: a variação (0.0.0.1) ou não (0.0.0.0) dos IPs de origem/destino;
- **timeout**: o tempo de duração em segundos.

```
/opt/MoonGen/build/MoonGen /opt/MoonGen/examples/netronome-packetgen/packetgen.lua \
    -tx 0 -rx 1 --src-ip 10.0.3.10 -sipv 0.0.0.1 \
    --dst-ip 10.0.4.10 --dipv 0.0.0.0 --timeout [X]
```
A recuperação dos valores armazenados nos registradores foi realizada com o códgo a seguir:


```
while :; do
    regHex="$(rtecli -p 20206 registers get -r $2 | tr '\n' ' ')"
    echo "[0]:"$(( 16#${regHex:4:8} ))" [1]:"$(( 16#${regHex:18:8} ))" [2]:"$(( 16#${regHex:32:8} ))" [3]:"$(( 16#${regHex:46:8} ))
done
```

## Suporte

Este software não possui nenhuma forma de suporte. 
