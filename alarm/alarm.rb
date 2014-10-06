#!/usr/bin/env ruby

#Assumes use of ruby alarm.rb or ruby alarm.rb -r [log file], any other useage may cause error
#ruby alarm.rb will intercept live packets to en0 and log any credit card leaks, null scans or Xmas scans
#ruby alarm.rb -r [log file] will analyze the log file for http errors, Nmap attacks and shell attacks

if ARGV.length == 0
	require 'packetfu'

	pkt_array = PacketFu::Capture.new(:iface => 'en0', :start => true, :promisc => true)

	#Credit card regex that is used to 
	credit_card_regex = ['4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}','3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}','\d{4}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}']

	count = 1
	attack = ""
	 pkt_array.stream.each do |p|
		 	current_attack = false
			pkt = PacketFu::Packet.parse(p)
			if pkt != nil and (pkt.class == PacketFu::TCPPacket or pkt.class == PacketFu::UDPPacket or pkt.class == PacketFu::ARPPacket)
				protocol = pkt.proto()[-1]
				begin
					source = pkt.ip_saddr
				rescue
					next
				end
				#Loads TCP flags if applicable and gets port number
				flags = nil
				payload = pkt.payload().each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
				if pkt.class == PacketFu::TCPPacket
					port = pkt.tcp_dst
					flags = pkt.tcp_flags
				elsif pkt.class == PacketFu::UDPPacket
					port = pkt.udp_dst				
				else
					port = 0
				end				
				#detects Xmas scan
				if flags and flags.fin == 1 and flags.psh == 1 and flags.urg == 1
					current_attack = true
					attack = "Xmas scan"
				end
				#detects Null scan
				if flags and flags.fin == 0 and flags.psh == 0 and flags.rst == 0 and flags.syn == 0 and flags.urg == 0 and flags.ack == 0
					current_attack = true
					attack = "Null scan"
				end
				#detects credit card numbers over HTTP
				if port == 80
					credit_card_regex.each do |reg|
						if "/#{reg}/".match(pkt.payload()) and pkt.payload() != ""
							puts "#{count}. ALERT: Credit card leaked in the clear from #{source} (#{protocol}) (#{payload})"
							count += 1
						end
					end
				end
				# Prints out current attack if detected
				if current_attack
					puts "#{count}. ALERT: #{attack} is detected from #{source} (#{protocol}) (#{payload})!"
					count += 1
				end
			end
	 end
else
	require 'apachelogregex'
	#Format of the log file
	format = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
	#creates a log file parser
	parser = ApacheLogRegex.new(format)
	log_file = ARGV.last
	count = 1
	File.open(log_file, 'r') do |f|
  		f.each_line do |line|
  			current_attack = false
  			parsed = parser.parse(line)
  			#checks for hex in the url indicating a shell attack
  			if /\\x[0-9a-fA-f]{2}/.match(parsed['%r'])
  				attack = "Shellcode"
				current_attack = true
			#Checks for Nmap in the user agent indicating an nmap scan
			elsif /Nmap Scripting Engine/.match(parsed["%{User-Agent}i"])
				attack = "Nmap scan"
				current_attack = true
			#checks for any http codes in the 400 range indicating an http error
  			elsif parsed['%>s'].to_i / 400 == 1
  				attack = "HTTP error"
  				current_attack = true
  			end
  			#Prints out the detected error
  			if current_attack
  				source = parsed["%h"]
  				payload = parsed["%r"].gsub(/HTTP\/[0-9]\.[0-9]/,'')
				puts "#{count}. ALERT: #{attack} is detected from #{source} (HTTP) (#{payload})!"
				count += 1
			end
  		end
  	end
end