Requirements
============
gem install packetfu [--user-install]

gem install pcaprub [--user-install]


Usage
=====

ruby spoofit.rb {interface} {T|F} {T|F} [victim IP] [router IP] 
Argument 1: Specify the poisoning / listening interface
Argument 2: Verbose output?
Argument 3: Do you want to perform Arp Poisoning? (This is left as an option to give you the opportunity to handle
            traffic monitoring on your own if so desired)
Argument 4: Specify the victim IP address (Only needed if Arp Poisoning)
Argument 5: Specify the router IP address (Only needed if Arp Poisoning)

e.g.:

ruby spoofit.rb en0 T T $1 10.0.2.25
