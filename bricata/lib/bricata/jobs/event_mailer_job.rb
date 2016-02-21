module Bricata
  module Jobs
    class EventMailerJob < Struct.new(:sid, :cid, :email, :hosturl)

      def perform
        # EventMailer.event_information(@event, email[:to], email[:subject], email[:body], @user).deliver
        # Delayed::Job.enqueue(Bricata::Jobs::EventMailerJob.new(params[:sid], params[:cid], params[:email]))
        
        @event ||= Event.get(sid, cid)
        @user ||= User.get(email[:user_id])
        EventMailer.event_information(@event, email[:to], email[:subject], email[:body], @user, hosturl).deliver
      end

    end
  end
end
