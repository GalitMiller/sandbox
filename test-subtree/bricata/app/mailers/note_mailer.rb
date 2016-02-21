class NoteMailer < ActionMailer::Base

  def new_note(note)
    @note = note
    @event = @note.event
    @emails = []
    
    User.all.each do |user|
      @emails << "#{user.name} <#{user.email}>" if user.accepts_note_notifications?(@event)
    end

    @from = (Setting.email? ? Setting.find(:email) : "bricata@bricata.com")

    mail(:to => @emails, :from => @from, :subject => "[Bricata] New Event Note Added")
  end

end
