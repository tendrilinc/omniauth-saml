require "base64"
require "uuid"
require "zlib"
require "cgi"

module OmniAuth
  module Strategies
    class SAML
      class AuthRequest

        def create(settings, params = {})
          uuid = "_" + UUID.new.generate
          time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

          request =
            "<samlp:AuthnRequest #{'ForceAuthn="true"' if settings[:force_auth]} xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{uuid}\" Version=\"2.0\" IssueInstant=\"#{time}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"#{settings[:assertion_consumer_service_url]}\">" +
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings[:issuer]}</saml:Issuer>\n" +
            "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"#{settings[:name_identifier_format]}\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n"

          if settings[:requested_authn_context]
            request << "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">"
            unless settings[:authn_context_class_ref].nil? || settings[:authn_context_class_ref].empty?
               request << "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings[:authn_context_class_ref]}</saml:AuthnContextClassRef>\n"
            end
            request << "</samlp:RequestedAuthnContext>"
          end

          request << "</samlp:AuthnRequest>"

          OmniAuth.logger.send :info, "********************************************"
          OmniAuth.logger.send :info, "           SAMLRequest from AuthRequest"
          OmniAuth.logger.send :info, request
          OmniAuth.logger.send :info, "********************************************"

          if settings[:use_post_binding]
            base64_request    = Base64.encode64(request)
          else
            deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
            base64_request    = Base64.encode64(deflated_request)
          end

          encoded_request   = CGI.escape(base64_request)
          delimiter =
            if settings[:idp_sso_target_url].include?('?')
              '&'
            else
              '?'
            end

          request_params    = "#{delimiter}SAMLRequest=" + encoded_request

          params.each_pair do |key, value|
            request_params << "&#{key}=#{CGI.escape(value.to_s)}"
          end

          OmniAuth.logger.send :info, "********************************************"
          OmniAuth.logger.send :info, "           request_params from AuthRequest"
          OmniAuth.logger.send :info, request_params
          OmniAuth.logger.send :info, "********************************************"

          settings[:idp_sso_target_url] + request_params
        end

      end
    end
  end
end
