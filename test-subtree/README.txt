
This is snapshot of Bricata server, which is rebranded version of Snorby.


Workaround for problem with flash messages
==========================================

For workaround of problem with flashing messaged in Ruby on Rails and
sessions in JSON, file flash.rb in actionpack gem is patched, file:
    /usr/local/rvm/gems/ruby-1.9.3-p551/gems/actionpack-3.1.12/lib/action_dispatch/middleware/flash.rb

these symbols are removed at line 7:

    session["flash"] || 

Whole 7th line now looks:

    @env[Flash::KEY] ||= (Flash::FlashHash.new).tap(&:sweep)

