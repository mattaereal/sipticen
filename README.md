# SIPTICEN
**Si**mple **P**acket **T**racking **i**n **C**ORE **E**mulated **N**etworks

*Made as a University final project for UNICEN, Tandil, Argentina.*

[Here's the link to the official project document (spanish)](https://docs.google.com/document/d/1HbZvZ77IhtSvhVqXkAxqf3R0vytGIzPtTb3nbirNH58/edit?usp=sharing)

# About

This tool was developed as a result of a final project for the chair Data Communication (I & II) of the university of Tandil [**UNICEN**](exa.unicen.edu.ar), Buenos Aires, Argentina.

Its purpose is to perform and convey an analysis of a network capture (**PcapNG**), obtained from a [**CORE**](http://www.nrl.navy.mil/itd/ncs/products/core) (Common Research Emulator) Network Topology, showing the results in the most possible human-redable way.

**Core topology sample screenshot**
![alt text][core-topology]

[core-topology]: https://i.imgur.com/MFbSrwv.png "Core topology sample"

### How

The interesting thing here, is that by using this tool you will be able to trace back a specified IP datagram through the network by applying filters of your desire.

You can start by applying common filters like source IP address - destination IP address, if it's TCP/UDP/ICMP, source port - destination port, etc. When you reduced your search to what you expected, you can trigger the trace flag in order to see how, when and where that packet/s traveled across the network's topology.

# Before installing

Since the main purpose of the tool is based over a **PcapNG** capture, you may use the ones provided in the sample folder **`misc/pcaps/`**, or make one yourself.

In order to get a capture from all the emulated **CORE** topology, you can do it manually via Wireshark gui by starting the capture on the *any* interface.

But here it is an *alternative* for the ones who rather prefer doing it by cli, or using *tshark*.

### Listing all interfaces
```
matt@cdd% tshark -D
1. eth0
2. nflog
3. nfqueue
4. n1.eth0.231
5. n1.eth1.231
6. n1.eth2.231
7. n2.eth0.231
8. n2.eth1.231
9. n2.eth2.231
10. n3.eth0.231
11. n3.eth1.231
12. b.4.35947
13. n5.eth0.231
14. n6.eth0.231
15. n7.eth0.231
16. n8.eth0.231
17. n9.eth0.231
18. b.908.35947
19. b.5688.35947
20. b.17756.35947
21. b.37909.35947
22. b.52969.35947
23. any
24. lo (Loopback)
```

### Capturing on *any*
```
matt@cdd% tshark -i any -w captura.pcapng -F pcapng
Capturing on 'any'
```

# Installation
1. First you need to have **pip2** previously installed and the latest version of wireshark ( latest stable is 1.12.5):

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

## Alternative installation
1. Install **pip2** as before.
2. Install virtualenv via pip2:

`# pip2 install virtualenv`

3. Inside the project create a virtualenv:

`# virtualenv venv`

4. Activate the virtual environment from the project:

`# source venv/bin/activate`

5. Install the requirements via pip2 inside the virtualenv.

`(venv)# pip2 install -r requirements.txt`

6. Run sipticen as shown on the sections below.
7. Deactivate the virtual env by typing:

`# deactivate`

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

## English
The captures being used can be found in the folder misc/pcaps.

The sample topology in xml format is also inside misc/core.

### ICMP
* Simple search filter between 2 hosts:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp`

* Search with identification field filter:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --icmp-ident 28`

* Previous search but hiding broadcast ifaces:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --icmp-ident 28 --hide-bcast`

### UDP
 * Search with UDP protocol filter:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.89.199 --udp --udp-proto NTP`

* Search with port filter:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 200.49.130.41 --udp --udp-port 53`

### TCP
* Search with TCP protocol filter:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-proto HTTP`

* Search with port filter:

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-port 80`

### Tracing
* Displaying the route of a packet through the current network topology:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --ip-id 16034 --trace --hide-bcast`

* With different packets from any protocol that satisfy the criteria:

`$ ./sipticen.py -f dump4.pcapng --search --src 10.0.4.20 --dst 10.0.5.10 --icmp --trace --hide-bcast`

### Print readable
You can add a way of printing in a humanly legible way the information of each layer, for each packet, from the previously shown filters.

`$ ./sipticen.py -f dump3.pcapng --search --src 192.168.1.103 --dst 91.189.90.41 --tcp --tcp-proto HTTP --ip-id 43084 --print-readable`

### CORE
* Parsing and displaying basic topology information:

`$ ./sipticen.py --parse misc/core/topology_sample.xml `

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


# Comentarios (spanish)

Como se puede ver el código actualmente se encuentra subido a github, bajo la licencia MIT, en dónde se puede clonar sin problema usando git, ya que es de acceso público.

En principio se había comenzado a desarrollar la herramienta utilizando **Scapy**, pero las problemáticas que posee al no poder utilizar el formato de captura **PcapNG** hicieron que sea limitante el uso del mismo. El formato **PcapNG** posee determinados metadatos que eran fundamentales para la realización de este trabajo, como por ejemplo la identificación de cada interfaz en donde fué tomada la captura dentro de cada frame.

Se utilizó **PyShark** como alternativa a **Scapy**, pero éste también presentaba limitaciones. El módulo hace un llamado (subprocess.call) al binario **tshark** con la captura, y éste devuelve un **XML** en formato **PSML** (Packet Summary Markup Language). Por ende era imposible obtener el formato **RAW** de cada paquete, para poder guardar una selección de ellos en una captura aparte. Es por ello que se agregó la opción **--print-readable** como una alternativa más para observar los paquetes.

# Observations (english)

In the beggining of the development of the tool, the core module being used was **Scapy**, but starting from the fact that **Scapy** can't work with PcapNG files, which are a prerequisite for this to work (since PcapNG saves metadata on each packet which is totally necessary, such as the interface id on where the frame was captured), made me rethink of using another one. 

So I switched to **PyShark** as an alternative, but this module also had a few limitations. **PyShark** makes a *subprocess.call* to the binary **tshark** with the capture, and this returns an **XML** in **PSML** (Packet Summary Markup Language) format. And it also did not have a way to save a list of desired packets to a new capture file. Thus, it was impossible for me to save a selection of packets to disk, neither patch the parser in runtime to get the **RAW** format of each packet to manually save them. So as a workaraound I decided to use the flag **--print-readable** as an option to see the detailed packet information in text.
