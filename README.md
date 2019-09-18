# AF_XDP Test Environment Inside Docker

This example is meant as a test environment to check the feasibility and performance of AF_XDP inside a docker network (Containers
communicating via the [veth driver](https://github.com/torvalds/linux/blob/master/drivers/net/veth.c)).

## Test Setup

We have a _Client_ and a _Server_ running a simple HTTP server and [iperf3](https://iperf.fr/). Both containers are reachable in the
Docker network (CIDR: `172.16.239.0/24`) via IP `172.16.239.13` (_Client_) and `172.16.239.14` (_Server_).

To intercept the traffic via AF_XDP, we put a _Router_ container (IP `172.16.239.13`) in between. The router is
rewriting the source and destination IP of each incoming packet. 

If coming from the _Client_, the destination IP is rewritten the _Server_'s IP and the other way around. 
The source IP is set to the _Router_'s IP, to ensure that packets are sent back to the _Router_.

If the _Client_ is now connecting to the _Router_, the traffic goes to the _Server_ via the _Router_. 
The forward flow (`FF`) and backward flow (`BF`) looks like this:
 
```
+-------------------+          +-------------------+          +-------------------+
|                   |          |                   |          |                   |
|                   |    FF    |                   |    FF    |                   |
|      Client       +--------->+       Router      +--------->+       Server      |
|  (172.16.239.13)  |    BF    |  (172.16.239.12)  |    BF    |  (172.16.239.14)  |
|                   |<---------|                   |<---------|                   |
|                   |          |                   |          |                   |
+-------------------+          +-------------------+          +-------------------+
```

> Additionally, the router also sends ARP requests to get the MAC address of the _Server_.

The test spends some time rewriting the packets. This could be avoided by placing _Client_ and _Server_
in different networks and attaching two interfaces (one for each network) to the router.
However, for simplicity we just wanted one network interface to be handled by AF_XDP. 

## Run the Example

To run the example, you'll need to install Docker (tested with version 19.03) 
on a Linux 5.1 kernel based system and start:

    $ ./start                   # run this example
    $ ./stop                    # stop running example


Or you want to run this example step by step you can following commands:

    $ ./huge 				# mount huge pages (required by the example)
    $ docker-compose build		# build example Docker images
    $ docker-compose up -d		# run the example
    $ docker-compose logs -f <role> 	# check log message of role
    					# here role could be router, client or service
    $ docker-compose down		# stop running example
    
After running this test case, you should get the results shown in the [./result](./result) directory.
