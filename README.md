# SIPTICEN
**Si**mple **P**acket **T**racking **i**n **C**ORE **E**mulated **N**etworks

*This tool was made as a final project for Data Communication I and II from UNICEN, Tandil, Argentina.*

[Here's the link to the official project document (spanish)](https://docs.google.com/document/d/1HbZvZ77IhtSvhVqXkAxqf3R0vytGIzPtTb3nbirNH58/edit?usp=sharing)

# Installation
1. First you need to have **pip2** previously installed.

  **Debian based:**
  
  `$ sudo apt-get install python-pip`

  **Arch linux:**
  
  `$ sudo pacman -S python2-pip`
  
  **CentOS / RHEL / Fedora**
  
  `$ sudo yum install python-pip`
  
  **Generic**
  
  `$ curl https://raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py | python2.7`

2. You have to check if all the dependencies are met using the following script:

  `python2 check_deps.py`

3. And after that everything should be set for using the tool.

# Tool help

## English
```
usage: sipticen.py [-h] [-m] [-r PREAD] [-w PWRITE] [--parse PARSE] [--search]
                   [-f FILE] [-s SRC] [-d DST] [-i IP_ID] [-t] [--hide-bcast]
                   [--print-readable] [--icmp] [--icmp-ident ICMP_IDENT]
                   [--tcp] [--tcp-port TCP_PORT] [--tcp-proto TCP_PROTO]
                   [--udp] [--udp-port UDP_PORT] [--udp-proto UDP_PROTO]

Matt's final project for CDD I & II.

optional arguments:
  -h, --help            show this help message and exit

merge:
  -m, --merge           Enables merge option.
  -r PREAD, --pread PREAD
                        --r *.pcap (only wildcards)
  -w PWRITE, --pwrite PWRITE
                        --w all.pcap

parse:
  --parse PARSE         --parse file.xml. Parses a Core XML topology.

search:
  --search              Enables search option.
  -f FILE, --file FILE  PcapNG file.
  -s SRC, --src SRC     Source IPv4 address.
  -d DST, --dst DST     Destination IPv4 address.
  -i IP_ID, --ip-id IP_ID
                        IP identification number.
  -t, --trace           Prints packet's trace through the topology
  --hide-bcast          Hides broadcast emulated interfaces packets.
  --print-readable      Prints packets in a readable format. Warning:
                        Flooding.

icmp:
  --icmp                Enables ICMP protocol.
  --icmp-ident ICMP_IDENT
                        Filter by ICMP ident.

tcp:
  --tcp                 Enables search over TCP protocol.
  --tcp-port TCP_PORT   80, 22, 21, 23, etc
  --tcp-proto TCP_PROTO
                        HTTP, SSH, FTP, etc

udp:
  --udp                 Enables search over UDP protocol.
  --udp-port UDP_PORT   53, 67, 68, 69, etc
  --udp-proto UDP_PROTO
                        DNS, DHCP, NTP, etc
```


## Spanish

```
matt@sipticen (master*)% ./sipticen.py -h
usage: sipticen.py [-h] [-m] [-r PREAD] [-w PWRITE] [--parse PARSE] [--search]
                   [-f FILE] [-s SRC] [-d DST] [-i IP_ID] [-t] [--hide-bcast]
                   [--print-readable] [--icmp] [--icmp-ident ICMP_IDENT]
                   [--tcp] [--tcp-port TCP_PORT] [--tcp-proto TCP_PROTO]
                   [--udp] [--udp-port UDP_PORT] [--udp-proto UDP_PROTO]

Matt's final project for CCDD I & II.

optional arguments:
  -h, --help            muestra este mensaje de ayuda y se cierra.

merge:
  -m, --merge           Habilita la opción juntar pcaps en uno sólo.
  -r PREAD, --pread PREAD
                        --r *.pcap (solamente wildcards)
  -w PWRITE, --pwrite PWRITE
                        --w all.pcap

parse:
  --parse PARSE         --parse file.xml. Parsea una topología en XML de CORE.

search:
  --search              Habilita la opción de búsqueda.
  -f FILE, --file FILE  Archivo de entrada PcapNG.
  -s SRC, --src SRC     Dirección IPv4 de origen
  -d DST, --dst DST     Dirección IPv4 de destino.
  -i IP_ID, --ip-id IP_ID
                        Número de identificación de la capa IP.
  -t, --trace           Imprime la trayectoria a través de los nodos de la topología.
  --hide-bcast          Esconde las interfaces broadcast generadas por la emulación.
  --print-readable      Imprime los paquetes en una manera legible.

icmp:
  --icmp                Habilita el filtro de búsqueda por el protocolo ICMP.
  --icmp-ident ICMP_IDENT
                        Habilita el filtro por el identificador ICMP.

tcp:
  --tcp                 Habilita el filtro de búsqueda para el protocolo TCP.
  --tcp-port TCP_PORT   Habilita el filtro de búsqueda para puertos: 80, 22, 21, 23..
  --tcp-proto TCP_PROTO Habilita el filtro de búsqueda por protocolos TCP: HTTP, SSH, FTP..
                        

udp:
  --udp                 Habilita el filtro de búsqueda para el protocolo UDP.
  --udp-port UDP_PORT   Habilita el filtro de búsqueda para puertos: 53, 67, 68, 69..
  --udp-proto UDP_PROTO Habilita el filtro de búsqueda para protocolos UDP: DNS, DHCP, NTP..
  ```


# Usage examples

## Spanish
Las capturas que se usarán pueden encontrarse en la carpeta misc/pcaps/.
Lo mismo con la estructura de la topología en formato xml, dentro de misc/core/.

### ICMP
* Búsqueda con filtro simple entre dos hosts:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp`

* Búsqueda con filtro por campo de identificación: 

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --icmp-ident 28`

* Búsqueda anterior ocultando interfaces broadcast:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --icmp-ident 28 --hide-bcast`

### UDP
 * Búsqueda con filtro por protocolo udp:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.89.199 --udp --udp-proto NTP`

* Búsqueda con filtro por puerto:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 200.49.130.41 --udp --udp-port 53`

### TCP
* Búsqueda con filtro por protocolo tcp:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-proto HTTP`

* Búsqueda con filtro por puerto:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-port 80`

### Tracing
* Mostrando el recorrido de un paquete a través de la topología:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --ip-id 16034 --trace --hide-bcast`

* Con distintos paquetes de cualquier protocolo que cumplen el criterio:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --trace --hide-bcast`

### Print readable
A cualquiera de las anteriores combinaciones se le puede agregar la manera de imprimir de una manera humanamente legible la información de cada capa del paquete con detalle.

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-proto HTTP --ip-id 43084 --print-readable`

### CORE
* Parseando y mostrando información básica de la topología ejemplo:

`$ ./sipticen.py --parse misc/core/topology_sample.xml `
                                                           

# Comentarios.

El código actualmente se encuentra subido a github, bajo la licencia MIT, en dónde se puede clonar sin problema usando git, ya que es público, y parte de esta documentación será agregada eventualmente para que esté al acceso de todos.

En principio se había comenzado a desarrollar la herramienta utilizando **Scapy**, pero las problemáticas que posee al no poder utilizar el formato de captura **PcapNG** hicieron que sea limitante el uso del mismo. El formato **PcapNG** posee determinados metadatos que eran fundamentales para la realización de este trabajo, como por ejemplo la identificación de cada interfaz en donde fué tomada la captura dentro de cada frame.

Se utilizó **PyShark** como alternativa a **Scapy**, pero éste también presentaba limitaciones. El módulo hace un llamado (subprocess.call) al binario **tshark** con la captura, y éste devuelve un **XML** en formato **PSML** (Packet Summary Markup Language). Por ende era imposible obtener el formato **RAW** de cada paquete, para poder guardar una selección de ellos en una captura aparte. Es por ello que se agregó la opción **--print-readable** como una alternativa más para observar los paquetes.
