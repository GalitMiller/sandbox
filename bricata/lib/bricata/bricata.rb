require "bricata/rule"

module Bricata
  
  def self.logger
    DataMapper::Logger.new($stdout)
  end
  
end
