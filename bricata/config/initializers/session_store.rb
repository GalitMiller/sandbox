# Be sure to restart your server when you modify this file.

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# Bricata::Application.config.session_store :data_mapper_store
# Be sure to restart your server when you modify this file.

class JSONVerifier < ActiveSupport::MessageVerifier
  def verify(signed_message)
    raise InvalidSignature if signed_message.blank?

    data, digest = signed_message.split("--")

    if data.present? && digest.present? && secure_compare(digest, generate_digest(data))
      ActiveSupport::JSON.decode(Base64.decode64(data.gsub('%3D','=')))
    else
      raise InvalidSignature
    end
  end

  def generate(value)
    data = Base64.strict_encode64(ActiveSupport::JSON.encode(value))
    "#{data}--#{generate_digest(data)}"
  end
end

module ActionDispatch
  class Cookies
    class SignedCookieJar
      def initialize(parent_jar, secret)
        ensure_secret_secure(secret)
        @parent_jar = parent_jar
        @verifier   = JSONVerifier.new(secret)
      end
    end
  end
end

Bricata::Application.config.session_store :cookie_store, :key => '_bricata_session', :expire_after => 15.minutes

