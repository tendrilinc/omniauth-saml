require 'omniauth'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy
      autoload :AuthRequest,      'omniauth/strategies/saml/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml/xml_security'

      option :name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      option :use_post_binding, false
      option :requested_authn_context, false
      option :authn_context_class_ref, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

      def request_phase
        request = OmniAuth::Strategies::SAML::AuthRequest.new
        redirect(request.create(options))
      end

      def callback_phase
        begin
          response = OmniAuth::Strategies::SAML::AuthResponse.new(request.params['SAMLResponse'])
          response.settings = options

          @name_id  = response.name_id
          @attributes = response.attributes

          if @name_id.nil? || @name_id.empty? || !response.valid?
            e = OmniAuth::Strategies::SAML::ValidationError.new('Invalid SAML Ticket')
            e.saml_response = response
            return fail!(:invalid_ticket, e)
          end

          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, OmniAuth::Strategies::SAML::ValidationError.new('Invalid SAML Response'))
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname],
          :last_name => @attributes[:last_name] || @attributes[:lastname]
        }
      end

      extra { { :raw_info => @attributes } }

      def redirect(uri)
        if options[:use_post_binding]
          r = Rack::Response.new
          saml_request = Rack::Utils.parse_query(URI.parse(uri).query).fetch('SAMLRequest')
          puts "********************************************"
          puts "           SAMLRequest from redirect"
          puts saml_request
          puts "********************************************"


          content = <<-CONTENT.gsub(/\s+/, ' ').strip
            <form method="post" action="#{options[:idp_sso_target_url]}">
               <input type="hidden" name="SAMLRequest" value="#{saml_request}" />
            </form>
            <script type="text/javascript" charset="utf-8">document.forms[0].submit();</script>
          CONTENT
          r.write(content)
          r.finish
        else
          super
        end
      end

      def fail!(message_key, exception = nil)
        if exception && exception.is_a?(ValidationError)
          log :error, exception.message
          log :error, "SAMLResponse => #{exception.saml_response.inspect}"
        end
        super
      end

      # Direct access to the OmniAuth logger, automatically prefixed
      # with this strategy's name.
      #
      # @example
      #   log :warn, "This is a warning."
      #   SAML::log :warn, "This is a warning."
      def self.log(level, message)
        OmniAuth.logger.send(level, "(saml) #{message}")
      end

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
