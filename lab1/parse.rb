#!/usr/bin/env ruby

require 'pry'
require 'pcap'

class Packet
  attr_accessor :endian, :file_handle
  def initialize(endian, file_handle)
    @endian = endian
    @file_handle = file_handle
  end

  def fetch
    self
  end
end

class HeaderParser
  def initialize(endian, file_handle)
    @endian = endian
    @file_handle = file_handle
  end

  def read_next(file, bytes, endian)
    string = file.read(bytes).unpack('H*').first
    if endian == :little
      string = string.scan(/../).reverse.join('')
    end

    string
  end
end

class PcapFileHeaderParser < HeaderParser
  attr_accessor :major_version, :minor_version, :time_zone_offset, :time_stamp_accuracy, :snapshot_length, :link_layer_type, :link_layer
  def initialize(endian, file_handle)
    super(endian, file_handle)
  end

  def parse
    @major_version = read_next(@file_handle, 2, @endian).to_i
    @minor_version = read_next(@file_handle, 2, @endian).to_i
    @time_zone_offset = read_next(@file_handle, 4, @endian).to_i
    @time_stamp_accuracy = read_next(@file_handle, 4, @endian).to_i
    @snapshot_length = @file_handle.read(4).unpack('V').first
    @link_layer_type = read_next(@file_handle, 4, @endian).to_i
    @link_layer = lookup_link_layer(@link_layer_type.to_i)

    puts "Finished parsing the pcap file header: #{self.inspect}"
    binding.pry
    self
  end

  private

  def lookup_link_layer(link_layer_type)
    return [nil, :LINKTYPE_ETHERNET][link_layer_type]
  end
end

class PcapReader
  attr_reader :file_handle, :endian, :file_header, :packets
  def initialize(file_name = "net.cap")
    @file_handle = open(file_name, "rb")
  end

  def get_endian
    @endian = @file_handle.read(4).unpack('H*').first == 'd4c3b2a1' ? :little : :big
  end

  def parse
    get_endian

    @file_header = PcapFileHeaderParser.new(@endian, @file_handle).parse
    binding.pry
    @packets = []

    while !@file_handle.eof?
      @packets << Packet.new(@endian, @file_handle).fetch
    end
    binding.pry
  end
end

reader = PcapReader.new
binding.pry
