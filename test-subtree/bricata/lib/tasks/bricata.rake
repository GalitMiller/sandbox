# Bricata - All About Simplicity.
#
# Copyright (c) 2014 Bricata, LLC
#
require "./lib/bricata/jobs"
require "./lib/bricata/worker"

namespace :bricata do

  desc 'Setup'  
  task :setup => :environment do
        
    Rake::Task['secret'].invoke
    
    # Create the bricata database if it does not currently exist
    Rake::Task['db:create'].invoke
    
    # Bricata update logic
    Rake::Task['bricata:update'].invoke
  end
  
  desc 'Update Bricata'
  task :update => :environment do

    # Setup the bricata database
    Rake::Task['db:autoupgrade'].invoke
    
    # Load Default Records
    Rake::Task['db:seed'].invoke

    # Restart Worker
    Rake::Task['bricata:restart_worker'].invoke
  end

  desc 'Update Bricata DB'
  task :dbupdate => :environment do

    # Setup the bricata database
    Rake::Task['db:autoupgrade'].invoke
    
    # Load Default Records
    Rake::Task['db:seed'].invoke
  end

  desc 'Remove Old CSS/JS packages and re-bundle'
  task :refresh => :environment do
    `jammit`
  end

  desc 'Start Bricata Worker if not running'
  task :start_worker => :environment do

    if Bricata::Worker.running?
      exit 0
    end
    
    # otherwise, restart worker.
    Rake::Task['bricata:restart_worker'].invoke
  end

  desc 'Restart Worker/Jobs'
  task :restart_worker => :environment do

    if Bricata::Worker.running?
      puts '* Stopping the Bricata worker process.'
      Bricata::Worker.stop
    end

    count = 0
    stopped = false
    while !stopped 
      
      stopped = true unless Bricata::Worker.running?
      sleep 5 

      count += 1
      if count > 10
        STDERR.puts "[X] Error: Unable to stop the Bricata worker process."
        exit -1
      end
    end

    unless Bricata::Worker.running?
      puts "* Removing old jobs"
      Bricata::Jobs.find.all.destroy

      puts "* Starting the Bricata worker process."
      Bricata::Worker.start
      
      count = 0
      ready = false
      while !ready 
        
        ready = true if Bricata::Worker.running?
        sleep 5 

        count += 1
        if count > 10
          ready  = true
        end
      end


      if Bricata::Worker.running?
        Bricata::Jobs.find.all.destroy
        puts "* Adding jobs to the queue"
        Bricata::Jobs.run_now!
      else
        STDERR.puts "[X] Error: Unable to start the Bricata worker process."
        exit -1
      end
    end

  end
  
  desc 'Soft Reset - Reset Bricata metrics'
  task :soft_reset => :environment do
    
    # Reset Counter Cache Columns
    puts 'Reseting Bricata metrics and counter cache columns'
    Severity.update!(:events_count => 0)
    Sensor.update!(:events_count => 0)
    Signature.update!(:events_count => 0)

    puts 'This could take awhile. Please wait while the Bricata cache is rebuilt.'
    Bricata::Worker.reset_cache(:all, true)
  end
  
  desc 'Hard Reset - Rebuild Bricata Database'
  task :hard_reset => :environment do
    
    # Drop the bricata database if it exists
    Rake::Task['db:drop'].invoke
    
    # Invoke the bricata:setup rake task
    Rake::Task['bricata:setup'].invoke
    
  end
  
end
