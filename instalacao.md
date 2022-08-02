# Instalação 

A instalação e o desenvolvimento foram realizados em um SO *Ubuntu 16.04.7 LTS* com kernel *(GNU/Linux 4.4.0-210-generic*, utilizando o *NFP SDK 6.1.0.1*. Os procedimentos seguidos para instalação dos *softwares* e *drivers* seguiram o descrito nas páginas da Netronome:

- [Driver Linux](https://help.netronome.com/support/solutions/articles/36000050148-agilio-smartnic-linux-driver-dkms-) - [Github](https://github.com/Netronome/nfp-drv-kmods)
- [Firmware básico](https://help.netronome.com/support/solutions/articles/36000049975-basic-firmware-user-guide)
- [Suporte DPDK SR-IOV](https://help.netronome.com/support/solutions/articles/36000020802-enabling-dpdk-sr-iov-support)
- [MoonGen]()https://github.com/emmericp/MoonGen/blob/master/examples/netronome-packetgen/Readme.txt)

## Driver Personalizado

Para carregar um *driver* desenvolvido em foi necessários altear o modo de carregamento conforme demonstrado abaixo. Os comandos abaixo fazem com que o driver do kernel seja 
carregado com o modo SDK. 

```
rmmod nfp
modprobe nfp nfp_dev_cpp_cpp=1 nfp_pf_netdev=0
```

Suporte a SR-IOV e ARI devem estar habilitados na bios para permitir o
carregamentos do driver e a criação das virtual functions. Para verificar
se a placa suporta essa duas funcionalidades, pode ser utilizados os 
comandos abaixo (fonte):

```
lspci | grep Netronome: retorna a placa do o ID do dispositivos
lspci -v : retorna detalhes do dispositivo
```