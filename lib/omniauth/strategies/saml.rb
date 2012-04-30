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

          return fail!(:invalid_ticket, 'Invalid SAML Ticket') if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, 'Invalid SAML Response')
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

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
