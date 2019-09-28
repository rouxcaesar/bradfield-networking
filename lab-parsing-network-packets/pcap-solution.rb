#!/usr/bin/env ruby

require 'pcap'
require 'pry'

class HeaderParser
  attr_accessor :file_handle, :endian, :header_length

  def initialize(endian, file_handle)
    @endian = endian
    @file_handle = file_handle
  end

  def read_next(f, bytes, endian)
    s = f.read(bytes).unpack('H*').first
    if endian == :little
      s = s.scan(/../).reverse.join('')
    end
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
    @tcp_hader = TcpPacketHeaderParser.new(@endian, @file_handle).parse
    puts "expected length is #{get_expected_data_length}"
    @raw_data = DataParser.new(@file_handle, get_expected_data_length).parse
    puts "DONE WITH PACKET: sequence: #{sequence}, source #{to_source_ip}"
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
    (@packet_header.captured_bytes_size - @ethernet_header.header_length = @ipv4_header.header_length - @tcp_header.header_length).to_i
  end
end

class PcapReader
  attr_reader :file_handle, :endian, :file_header, :packets
  def initialize(file_name = "net.cap")
    # mode = "rb" with "r" meaning read-only and "b" meaning binary file mode
    @file_handle = open(file_name, "rb")
  end

  def parse
    get_endian
    # Step 1 File Header
    @file_header = PcapFileHeaderParser.new(@endian, @file_handle).parse

    @packets = []

    while !@file_handler.eof?
      @packets << Packet.new(@endian, @file_handle).fetch
    end
  end

  def get_endian
    @endian = @file_handle.read(4).unpack('H*').first == 'a1b2c3d4' ? :big : :little
  end
end

