class JobsController < ApplicationController

  before_filter :require_administrative_privileges

  def index
    @jobs = Bricata::Jobs.find.all
    @process = Bricata::Worker.process
    
    respond_to do |format|
      format.html
      format.js
      format.xml  { render :xml => @jobs }
    end
  end

  def last_error
    @job = Bricata::Jobs.find.get(params[:id])
    render :layout => false
  end
  
  def handler
    @job = Bricata::Jobs.find.get(params[:id])
    render :layout => false
  end

  def show
    @job = Bricata::Jobs.find.get(params[:id])

    respond_to do |format|
      format.html # show.html.erb
      format.xml  { render :xml => @job }
    end
  end

  def edit
    @job = Bricata::Jobs.find.get(params[:id])
  end

  def update
    @job = Bricata::Jobs.find.get(params[:id])

    respond_to do |format|
      if @job.update(params[:job])
        format.html { redirect_to(@job, :notice => 'Job was successfully updated.') }
        format.xml  { head :ok }
      else
        format.html { render :action => "edit" }
        format.xml  { render :xml => @job.errors, :status => :unprocessable_entity }
      end
    end
  end

  def destroy
    @job = Bricata::Jobs.find.get(params[:id])
    
    if @job.blank?
      redirect_to jobs_url
    else
      @job.destroy
      respond_to do |format|
        format.html { redirect_to(jobs_url) }
        format.xml  { head :ok }
      end
    end
    
  end
end
