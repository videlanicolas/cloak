# Cloak
Covert IP services running on Linux, based on a specific IP ID number.

Cloak is a Python script that injects an NFQUEUE line in your iptables, forwarding the traffic of a **newly created** connection (can be TCP, UDP, ICMP, etc...) to a python script who will then decide if accept the packet or drop it (and eventually send a TCP RST, ICMP Unreachable, etc...)

### Features / Improvements
  - [x] Use a PSK to hash and create the accepted IP ID value.
  - [x] Add optional machine's timestamp value to hash and create the accepted IP ID value, thus changing the IP ID value.
  - [x] Make it work with TCP services (SSH, Apache, MySQL and similar).
  - [ ] Make it work with UDP services (DNS, NTP, SNMP and similar).
  - [ ] Make it work with ICMP services.
  - [ ] Generalize configuration via a configuration file.
  - [ ] Add optional RST or drop action.
  - [ ] Make the client work in Windows & Mac OSX.
  - [ ] Mitigate a DoS on the port.
  - [ ] Change correct IP ID value on each TCP RST that the server sends.
  - [ ] Make it a service on Linux, so people can start/stop/reset when they want.
  - [ ] Migrate the code to C for better performance.

### Installation
### Running the server side script
### Running the client side script
