#!/usr/bin/env ruby
require 'packetfu'



if ARGV.length == 0
	pkt_array = PacketFu::Capture.new(:iface => 'en0', :start => true, :promisc => true)
	caught = false

	credit_card_regex = ['4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}']

	count = 1
	current_attack = false
	attack = ""
	 pkt_array.stream.each do |p|
		 	current_attack = false
			begin
				pkt = PacketFu::Packet.parse(p)
				protocol = pkt.proto()[-1]
				source = pkt.ip_saddr
				flags = nil
				payload = pkt.payload().each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
				if pkt.class == 'PacketFu::TCPPacket'
					port = pkt.tcp_dst
					flags = pkt.tcp_flags
				elsif pkt.class == 'PacketFu::UDPPacket'
					port = pkt.udp_dst
				else
					port = 0
				end				
			rescue
				next
			end
			if flags and flags.fin == 1 and flags.psh == 1 and flags.urg == 1
				current_attack = true
				attack = "Xmas scan"
			end
			if flags and flags.fin == 0 and flags.psh == 0 and flags.rst == 0 and flags.syn == 0 and flags.urg == 0 and flags.ack == 0
				current_attack = true
				attack = "Null scan"
			end
			if port == 80
			credit_card_regex.each do |reg|
				if "/#{reg}/".match(pkt.payload()) and pkt.payload() != ""
					puts "#{count}. ALERT: Credit card leaked in the clear from #{source} (#{protocol}) (#{payload})"
					count += 1
				end
			end
			end

			if current_attack
				puts "#{count}. ALERT: #{attack} is detected from #{source} (#{protocol}) (#{payload})!"
				count += 1
			end
	 end
else
	log_file = ARGV.last


end