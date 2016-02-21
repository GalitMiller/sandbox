class SettingsController < ApplicationController

  before_filter :require_administrative_privileges

  def index
  end

  def create
    @params = params[:settings]
    @settings = Setting.all

    @settings.each do |setting|
      name = setting.name
      
      if @params.keys.include?(name)
        if @params[name].kind_of?(ActionDispatch::Http::UploadedFile)
          Setting.file(name, @params[name])
        else
          setting.update(:value => @params[name])
        end
      else
        setting.update(:value => nil) if setting.checkbox?
      end
    end

    redirect_to settings_path, :notice => 'Settings Updated Successfully.'
  end

  def update

  end

  def start_worker
    Bricata::Worker.start unless Bricata::Worker.running?
    redirect_to jobs_path
  end

  def start_sensor_cache
    Bricata::Jobs.sensor_cache.destroy! if Bricata::Jobs.sensor_cache?
    Delayed::Job.enqueue(Bricata::Jobs::SensorCacheJob.new(true), :priority => 1)
    redirect_to jobs_path
  end

  def start_daily_cache
    Bricata::Jobs.daily_cache.destroy! if Bricata::Jobs.daily_cache?
    Delayed::Job.enqueue(Bricata::Jobs::DailyCacheJob.new(false), :priority => 1, :run_at => Time.now.tomorrow.beginning_of_day)
    redirect_to jobs_path
  end
  
  def start_geoip_update
    Bricata::Jobs.geoip_update.destroy! if Bricata::Jobs.geoip_update?
    Delayed::Job.enqueue(Bricata::Jobs::GeoipUpdatedbJob.new(true), :priority => 1, :run_at => 10.minutes.from_now)
    redirect_to jobs_path
  end

  def restart_worker
    Bricata::Worker.stop
    Bricata::Worker.start
    redirect_to jobs_path
  end

end
