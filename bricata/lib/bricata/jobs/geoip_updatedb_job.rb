module Bricata
  module Jobs
    class GeoipUpdatedbJob < Struct.new(:verbose)
      
      def perform
        uri = if Bricata::CONFIG.has_key?(:geoip_uri)
          URI(Bricata::CONFIG[:geoip_uri])
        else
          URI("http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz")
        end

        resp = Net::HTTP.get_response(uri)

        gzip = lambda do |resp, file|
          gz = Zlib::GzipReader.new(StringIO.new(resp.body.to_s)) 
          file.write(gz.read)
        end

        normal = lambda do |resp, file|
          data = StringIO.new(resp.body.to_s)
          file.write(data.read)
        end

        if resp.is_a?(Net::HTTPOK)
          open("temp/tmp-bricata-geoip.dat", "wb") do |file|
            if uri.to_s.match(/.gz/)
              gzip.call(resp, file)
            else
              normal.call(resp, file)
            end
          end
        end

        if File.exists?("temp/tmp-bricata-geoip.dat")
          FileUtils.mv('temp/tmp-bricata-geoip.dat', 'config/bricata-geoip.dat', :force => true)
        end
        
        Bricata::Jobs.geoip_update.destroy! if Bricata::Jobs.geoip_update?

        Delayed::Job.enqueue(Bricata::Jobs::GeoipUpdatedbJob.new(false),
                               :priority => 1, 
                               :run_at => 1.week.from_now)
      rescue => e
        puts e
        puts e.backtrace
      end
    end
  end
end
