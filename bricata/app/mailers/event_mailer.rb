class EventMailer < ActionMailer::Base
  
  def event_information(event, emails, subject, note, user, hosturl)
    @event = event
    @user = user
    @emails = emails.split(',')
    @note = note
	@url = hosturl + view_events_path(:sid => @event.sid, :cid => @event.cid)

    @from = (Setting.email? ? Setting.find(:email) : "bricata@bricata.com")
    
    mail(:to => @emails, :from => @from, :subject => "[Bricata Event] #{subject}")
  end
  
end
