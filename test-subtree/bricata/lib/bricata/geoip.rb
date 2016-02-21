require 'geoip'

module Bricata
  module Geoip
   
    PATH = File.join(Rails.root.to_s, 'config', 'bricata-geoip.dat')

    FAKE_DATA = {
      :country_code2 => "N/A" 
    }

    def self.database?
      return false unless File.exists?(PATH)
      return false if File.zero?(PATH)
      File.open(PATH)
    end

    def self.lookup(ip)
      database = self.database?
      return FAKE_DATA unless database
      lookup = GeoIP.new(database).country(ip)
      lookup.to_hash
    rescue ArgumentError => e
      {}
    end

  end
end
