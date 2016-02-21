module Bricata
  
  class Worker < Struct.new(:action)

    @@pid_path = "#{Rails.root}/tmp/pids"
    
    @@pid_file = "#{Rails.root}/tmp/pids/delayed_job.pid"

    def perform
      
      case action.to_sym
      when :start
        Worker.start
      when :stop
        Worker.stop
      when :restart
        Worker.stop
        Worker.start
      when :zap
        Worker.zap
      end
      
    end

    def self.problems?
      worker_and_caches = (!Bricata::Worker.running? || !Bricata::Jobs.sensor_cache?)
      Setting.geoip? ? ( worker_and_caches || !Bricata::Jobs.geoip_update?) : worker_and_caches
    end

    def self.process
      if Worker.pid
        Bricata::Process.new(`ps -o ruser,pid,%cpu,%mem,vsize,rss,tt,stat,start,etime,command -p #{Worker.pid} |grep delayed_job |grep -v grep`.chomp.strip)
      end
    end

    def self.pid
      File.open(@@pid_file).read.to_i if File.exists?(@@pid_file)
    end

    def self.running?
      return true if File.exists?(@@pid_file) && !Worker.process.raw.empty?
      false
    end
    
    def self.start
      `#{Rails.root}/script/delayed_job start --pid-dir #{@@pid_path} RAILS_ENV=production`
    end
    
    def self.stop
      `#{Rails.root}/script/delayed_job stop --pid-dir #{@@pid_path} RAILS_ENV=production`
    end

    def self.restart
      `#{Rails.root}/script/delayed_job stop --pid-dir #{@@pid_path} RAILS_ENV=production`
      `#{Rails.root}/script/delayed_job start --pid-dir #{@@pid_path} RAILS_ENV=production`
    end
    
    def self.zap
      `#{Rails.root}/script/delayed_job zap --pid-dir #{@@pid_path} RAILS_ENV=production`
    end

  end
  
end
