#!/usr/bin/env ruby

# This is someone elses Ruby solution as well from class: https://github.com/andrewdollard/pcap-parser

# http://networkstatic.net/what-are-ethernet-ip-and-tcp-headers-in-wireshark-captures/
# IP Headers - https://en.wikipedia.org/wiki/IPv4#Source_address
require 'pcap'
require 'pry'

class HeaderParser
   attr_accessor :file_handle, :endian, :header_length

  def initialize(endian, file_handle)
    @endian = endian
    @file_handle = file_handle
  end

  def read_next(f, bytes, endian)
    # This unpacks everything into one string
    # - read returns a hex string like "\x00@"
    # - unpack('H*') converts that to the string representation of that, such as "0040"
    s = f.read(bytes).unpack('H*').first
    if endian == :little
      # scan(/../) will simply split the string into pieces with each piece containing 2 characters
      s = s.scan(/../).reverse.join('')
    end

    s
  end
end

class PcapFileHeaderParser < HeaderParser
  attr_accessor :major_version, :minor_version, :tz_offset, :tz_accuracy, :snapshot_length, :link_layer_type, :link_layer

  def initialize(endian, file_handle)
    # puts "file is #{file_handle}"
    super(endian, file_handle)
  end

  def parse
    @major_version = read_next(@file_handle, 2, @endian).to_i
    @minor_version = read_next(@file_handle, 2, @endian).to_i
    # A 4-byte time zone offset; this is always 0.
    @tz_offset = read_next(@file_handle, 4, @endian)
    # A 4-byte number giving the accuracy of time stamps in the file; this is always 0.
    @tz_accuracy = read_next(@file_handle, 4, @endian)
    # A 4-byte number giving the "snapshot length" of the capture; packets longer than the snapshot length are truncated to the snapshot length, so that, if the snapshot length is N, only the first N bytes of a packet longer than N bytes will be saved in the capture.
    @snapshot_length = @file_handle.read(4).unpack('V').first
    # a 4-byte number giving the link-layer header type for packets in the capture; see pcap-linktype(7) for the LINKTYPE_ values that can appear in this field.
    @link_layer_type = read_next(@file_handle, 4, @endian)
    @link_layer = lookup_link_layer(@link_layer_type.to_i)

    puts "Finished parsing the file header: #{self.inspect}"
    

    self
  end

  private

  def lookup_link_layer(link_layer_type)
    return [nil, :LINKTYPE_ETHERNET][link_layer_type]
  end
end

class PcapPacketHeaderParser < HeaderParser
  attr_accessor :captured_secs, :captured_ms, :captured_timestamp, :captured_bytes_size, :sent_bytes_size

  def initialize(endian, file_handle)
    super(endian, file_handle)
  end

  def parse
    # 4-byte value of time stamp of the approximate time the packet was captured; the time stamp consists of a , giving the time in seconds since January 1, 1970, 00:00:00 UTC,
    @captured_secs = @file_handle.read(4).unpack('V').first
    # 4-byte value, giving the time in microseconds or nanoseconds since that second, depending on the magic number in the file header.
    @captured_ms = @file_handle.read(4).unpack('V').first
    @captured_timestamp = Time.at(@captured_secs, @captured_ms)
    # 4-byte value giving the number of bytes of captured data that follow the per-packet header
    @captured_bytes_size = @file_handle.read(4).unpack('V').first
    # 4-byte value giving the number of bytes that would have been present had the packet not been truncated by the snapshot length. The two lengths will be equal if the number of bytes of packet data are less than or equal to the snapshot length.
    @sent_bytes_size = @file_handle.read(4).unpack('V').first

    puts "Finished parsing the packet header: #{self.inspect}"
    

    self
  end

  def captured_all?
    packet_header.captured_bytes_size == packet_header.sent_bytes_size
  end
end

class EthernetPacketHeaderParser < HeaderParser
  attr_accessor :destination_address, :source_address, :ethernet_type

  def initialize(endian, file_handle)
    @header_length = 14
    super(endian, file_handle)
  end

  def parse
    # https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
    @destination_address = read_next(@file_handle, 6, endian)
    @source_address = read_next(@file_handle, 6, endian)
    # The EtherType field is two octets long and it can be used for two different purposes. Values of 1500 and below mean that it is used to indicate the size of the payload in octets, while values of 1536 and above indicate that it is used as an EtherType, to indicate which protocol is encapsulated in the payload of the frame. When used as EtherType, the length of the frame is determined by the location of the interpacket gap and valid frame check sequence (FCS).
    @ethernet_type = read_next(@file_handle, 2, endian).to_i

    puts "Finished parsing the ethernet header: #{self.inspect}"
    

    self
  end
end

class Ipv4PacketHeaderParser < HeaderParser
  # https://en.wikipedia.org/wiki/IPv4

  attr_accessor :version, :internet_header_length, :dscp, :ecn, :total_length, :identification,
                :flags, :fragment_offset, :time_to_live, :protocol, :header_checksum, :source_ip,
                :destination_ip

  def initialize(endian, file_handle)
    super(endian, file_handle)
  end


  def parse
    # NOTE!!!!!!!: All of IP header is BIG endian. From wikipedia: "The fields in the header are packed with the most
    #              significant byte first (big endian), and for the diagram and discussion, the most significant bits
    #              are considered to come first (MSB 0 bit numbering)"
    # ALSO NOTE!!!! IP header requires bit level distinction, so need to basically parse the byte representation of the
    #               hexedicimal strings and then manually parse out the needed bits manually. This is a different approach
    #               than taking when can just read bytes wholly at a time and just auto convert them straight into the
    #               hexedecimal string representation

    first_byte = @file_handle.read(1).unpack('C*').first
    # 4 bits = First 4 bits The first header field in an IP packet is the four-bit version field.
    #          For IPv4, this is always equal to 4.
    # NOTE: to get the integer value of the first 4 bits just need to literally bit wise right shift the unsigned
    #       int value for the whole byte. example is that if it is 0100 1111 and all we want is 0100 then we just
    #       perform the bitwise shift to the right and get 0000 0100, which translates to 4
    @version = first_byte >> 4
    # 4 bits = The Internet Header Length (IHL) field has 4 bits, which is the number of 32-bit words.
    #          Since an IPv4 header may contain a variable number of options, this field specifies the size of the
    #          header (this also coincides with the offset to the data). The minimum value for this field is 5,[11]
    #          which indicates a length of 5 × 32 bits = 160 bits = 20 bytes. As a 4-bit field, the maximum value is
    #          15 words (15 × 32 bits, or 480 bits = 60 bytes).
    # NOTE: To get the last 4 bits, we just need to convert the first 4 bits all to 0. To do this we can use "bitwise and" operarator with the binary number for 0000 1111 which is 15.
    #       This will automatically convert all of the first 4 digits to 0s
    @internet_header_length = first_byte & 15

    second_byte = @file_handle.read(1).unpack('C*').first
    # NOTE: to get the integer value of the first 6 bits just need to literally bit wise right shift the unsigned
    #       int value for the whole byte over 2 bits. example is that if it is 0100 0101 and all we want is 0100 01 then we just
    #       perform the bitwise shift to the right twice and get 0100 01, which is 17
    # NOTE: In this scenario though we want the bit string to be completely filled
    #       so need to reformat at by filling in missing 0s for the expected length which is 6 bits
    @dscp = "%06b" % (second_byte >> 2)

    # NOTE: To get the last 2 bits, we just need to convert the first 6 bits all to 0. To do this we can use "bitwise and"
    #       operarator with the binary number for 0000 0011 which is 3. This will automatically convert all of the first 6
    #       digits to 0s.
    # NOTE: In this scenario though we want the bit string to be completely filled
    #       so need to reformat at by filling in missing 0s for the expected length which is 2 bits
    @ecn = "%02b" % (second_byte & 3)

    @total_length = read_next(@file_handle, 2, :big).to_i(16)
    @identification = read_next(@file_handle, 2, :big)

    next_2_bytes = @file_handle.read(2).unpack('C*')
    # 3 bits
    # NOTE: to get the integer value of the first 3 bits just need to literally bit wise right shift the unsigned
    #       int value for the whole byte. example is that if it is 0100 1111 and all we want is 0100 then we just
    #       perform the bitwise shift to the right and get 0000 0100, which translates to 4
    @flags = "%03b" % (next_2_bytes.first >> 5)

    # 13 bits
    # NOTE: To get the last 5 bits of the first byte, we just need to convert the first 3 bits all to 0.
    #       To do this we can use "bitwise and" operator with the binary number for 0001 1111 which is 31.
    #       This will automatically convert all of the first 3 digits to 0s.
    # NOTE: In this scenario though we want the bit string to be completely filled
    #       so need to reformat at by filling in missing 0s for the expected length which is 2 bits
    @fragment_offset = ("%05b" % (next_2_bytes.first & 31)) + ("%04b" % next_2_bytes[0].to_s(2))

    @time_to_live = read_next(@file_handle, 1, :big).to_i(16)


    protocol_int = read_next(@file_handle, 1, :big).to_i
    @protocol = get_protocol(protocol_int)
    @header_checksum = read_next(@file_handle, 2, :big)
    # For these we want the byte digit representation of each hexedecimal character, so not taking the hexedecimal string
    @source_ip = @file_handle.read(4).unpack("C*").join('.')
    @destination_ip = @file_handle.read(4).unpack("C*").join('.')

    if @internet_header_length != 5
      puts "internet header length is not 5 so need to handle parsing options: #{internet_header_length}"
      
      raise
    end

    @header_length = @internet_header_length * 4

    puts "Finished parsing the ipv4 header: #{self.inspect}"
    

    self
  end

  private

  def get_protocol(protocol_int)
    return :tcp if protocol_int == 6
    return :udp if protocol_int == 17
    :unsupported
  end
end


class TcpPacketHeaderParser < HeaderParser
  attr_accessor :packet_length,
                :source_port,
                :destination_port,
                :sequence_number,
                :ack_number,
                :data_offset,
                # 3 bits - should be 0
                :reserved,
                :ns,
                :cwr,
                :ece,
                :urg,
                :ack,
                :psh,
                :rst,
                :syn,
                :fin,
                :window_size,
                :checksum,
                :urgent_pointer,
                :options,
                :options_padding

  def initialize(endian, file_handle)
    super(endian, file_handle)
    @packet_length = packet_length
  end

  def parse
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    @source_port = @file_handle.read(2).unpack("H*").first.to_i(16)
    @destination_port = @file_handle.read(2).unpack("H*").first.to_i(16)
     # http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
    # Think this should be the hex int representation
    @sequence_number = @file_handle.read(4).unpack("H*").first.to_i(16)
    @ack_number = @file_handle.read(4).unpack("H*").first.to_i(16)

    next_byte = @file_handle.read(1).unpack('C*')
    # 4 bits - represented as int
    @data_offset = (next_byte[0] >> 4).to_i


    @reserved = "%03b" % (next_byte[0] & 14)

   # final 1 bit
    @ns = next_byte.first & 1

    # THIS IS PROBABLY IT
    flag_byte_string = @file_handle.read(1).unpack("B*").first
    @cwr = flag_byte_string[0]
    @ece = flag_byte_string[1]
    @urg = flag_byte_string[2]
    @ack = flag_byte_string[3]
    @psh = flag_byte_string[4]
    @rst = flag_byte_string[5]
    @syn = flag_byte_string[6]
    @fin = flag_byte_string[7]

    @window_size = @file_handle.read(2).unpack("H*").first.to_i(16)
    # Just keeping as hex string. Unclear what should be
    @checksum = @file_handle.read(2).unpack("H*").first

    @urgent_pointer = @file_handle.read(2).unpack("H*").first.to_i(16)

    # There is always at least 20 bytes used by required data. Any extra is used for options.
    @options = []
    (@data_offset - 5).times do
      # No clue whats in here so keeping as hex for now
      @options << @file_handle.read(4).unpack("H*").first.to_i(16)
    end

    @header_length = @data_offset * 4

    puts "Finished parsing the tcp header: #{self.inspect}"
    

    self
  end

end

class DataParser
  attr_accessor :file_hane, :expected_length_bytes, :raw_data

  def initialize(file_handle, expected_length_bytes)
    @file_handle = file_handle
    @expected_length_bytes = expected_length_bytes
  end

  def parse
    @raw_data = @file_handle.read(@expected_length_bytes).unpack("C*").flatten
    

    self
  end
end

class Packet
  attr_accessor :endian, :file_handle, :packet_header, :ethernet_header, :ipv4_header, :tcp_header, :raw_data

  def initialize(endian, file_handle)
    @endian = endian
    @file_handle = file_handle
  end

  def fetch
    puts "====\n"
    puts "STARTING NEW PACKET"
    @packet_header = PcapPacketHeaderParser.new(@endian, @file_handle).parse
    @ethernet_header = EthernetPacketHeaderParser.new(@endian, @file_handle).parse
    @ipv4_header = Ipv4PacketHeaderParser.new(@endian, @file_handle).parse
    @tcp_header = TcpPacketHeaderParser.new(@endian, @file_handle).parse
    puts "expected length is #{get_expected_data_length}"
    @raw_data = DataParser.new(@file_handle, get_expected_data_length).parse
    puts "DONE WITH PACKET: sequence: #{sequence}, source: #{to_source_ip}"
    puts "====\n\n\n"
    
    self
  end

  def sequence
    @tcp_header.sequence_number
  end

  def data
    @raw_data.raw_data
  end

  def to_source_ip
    @ipv4_header.destination_ip == "192.168.0.101"
  end

  private

  def get_expected_data_length
    (@packet_header.captured_bytes_size - @ethernet_header.header_length - @ipv4_header.header_length - @tcp_header.header_length).to_i
  end
end

class PcapReader
  attr_reader :file_handle, :endian, :file_header, :packets
  def initialize(file_name = "net.cap")
    @file_handle = open(file_name, "rb")
  end

  def parse
    get_endian
    # Step 1 File Header
    @file_header = PcapFileHeaderParser.new(@endian, @file_handle).parse

    @packets = []

    while !@file_handle.eof?
      @packets << Packet.new(@endian, @file_handle).fetch
    end
    binding.pry
  end

  def get_endian
    # endian is the ordering of bytes in a multi-byte value
    # little endian is when the ordering is with the least significant bytes ordered (stored) first
    # big endian is when the ordering is with the most significant bytes order (stored) first
    # unpack is a method that allows you to directly access the memory in which variables are stored.
    @endian = @file_handle.read(4).unpack('H*').first == 'a1b2c3d4' ? :big : :little
  end
end

reader = PcapReader.new
reader.parse

puts "Found #{reader.packets.size} packets"

final_packets = {}
reader.packets.each do |packet|
  if packet.to_source_ip
    final_packets[packet.sequence] = packet.data
  end
end

final_data = final_packets.sort_by do |seq, data|
  seq
end.map { |arr| arr[1].flatten }.flatten

headers = ""
previous_4 = []
loop do
  char = final_data.shift.chr
  headers += char
  previous_4.shift if previous_4.length == 4
  previous_4.push(char)

  # We need this b/c this is how the HTTP headers are terminated
  if previous_4 == ["\r", "\n", "\r", "\n"]
    break
  end
end


puts "http headers: #{headers}"

File.open('image.jpg', 'w') { |f| f.write(final_data.pack('C*')) }
`open image.jpg`
