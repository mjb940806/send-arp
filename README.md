# send-arp
[ref1](http://www.binarytides.com/c-program-to-get-ip-address-from-interface-name-on-linux/)
[ref2](http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c)

1. send ARP request to the sender
2. get the ARP reply (the sender's `MAC address`)
3. send ARP reply to the sender with the attacker's `MAC address` and the target's `IP address`

### OS
```
Ubuntu 16.04.2
```

### Language
```
C
```

### Compile & Execute
```
$ gcc -o arp arp.c -lpcap
```
```
$ sudo ./arp ens33 192.168.242.147 8.8.8.8
```

### Result
```
============= Send ARP =============
******* get attacker's info *******
attacker MAC 0:c:29:53:b3:dd 
attacker IP  192.168.242.180
******** get sender's info ********
sender MAC   0:c:29:48:20:4c 
sender IP    192.168.242.147
****** send infected packet *******
src MAC      0:c:29:53:b3:dd 
src IP       8.8.8.8
dst MAC      0:c:29:48:20:4c 
dst IP       192.168.242.147
====================================
```

