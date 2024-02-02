# Packet Sniffer

## Description

This is a simple packet sniffer that can be used to sniff packets on a network. It uses the scapy library to sniff packets and process them. It can be used to sniff packets on various interfaces.

## Usage

### Installation

If you're on a linux/debian based OS, you need to install the scapy library to use this program as it is not an inbuilt python library. You can install it using the following command:

``` bash
sudo apt-get install python3-scapy
```

After which you can clone the repository using the following command:

``` bash
git clone https://github.com/BjornOnGit/packet_sniffer.git
```

Move into the directory:

``` bash
cd packet_sniffer
```

### Running the program

If you're on a linux/debian based OS, you need to run the program as root to be able to sniff packets. You can do so by using the following command:

``` bash
sudo python3 sniffer.py
```

If you're on a windows OS, you can run the program as an admin to be able to sniff packets. You can do so by using the following command:

``` bash
python3 sniffer.py
```

If you're unsure about your interface name, you can use the following command to list all the available interfaces:

On linux/debian based OS:

``` bash
ifconfig 
```

On windows OS:

``` bash
ipconfig
```

In linux/debian based OS:

If you're on a wireless interface, your interface name will be something like wlan0 or wlan1.
If you're on a wired interface, your interface name will be something like eth0 or eth1.

In windows OS:
If you're on a wireless interface, your interface name will be something like Wi-Fi.
If you're on a wired interface, your interface name will be something like Ethernet.

### Functions

The program has the following functions:

1. sniff(interface) - This function is used to sniff packets on the specified interface. It takes in the interface name as a parameter.
When the sniff function is called, it calls the process_sniffed_packet function for each packet that is sniffed.
2. process_sniffed_packet(packet) - This function is used to process the sniffed packet. It takes in the packet as a parameter.

### Contributions

The project is open to contributions. You can contribute by adding new features or fixing bugs. For  major changes, please open an issue first to discuss what you would like to change or improve.

### Disclaimer

This program is for educational purposes only. The author is not responsible for any misuse of this program.

### License

This project is licensed under the MIT License - see the LICENSE.md file for details.
