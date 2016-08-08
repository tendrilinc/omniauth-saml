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
            if settings[:sign_requests].present?
              response << "
                <ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
                  <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>
                    <ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>
                    <ds:Reference URI='#_3738a24e8520a7ff251ef510cf23abbf52eec789'>
                      <ds:Transforms>
                        <ds:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'/>
                        <ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'>
                          <ec:InclusiveNamespaces PrefixList='xs' xmlns:ec='http://www.w3.org/2001/10/xml-exc-c14n#'/>
                        </ds:Transform>
                      </ds:Transforms>
                      <ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>
                      <ds:DigestValue>FW/z+bZ+zJMK77OJW5tHn/b9UwI=</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>bwD8w3Pv4KkKQQx5/IIVI0pmitgEdU5GMVyu8U8AKy7+TSMr2mOUQxwfVg3qZgS3+np4zFRF4MuTgdUNCfkOca2/V6CqyOfSyS7bxjM78ZRHNitB7KIT4b1i/3GSK8vWmoA2rl7T81QORnHZg/KZn3O8y4kpwJzpRiYZicnSU3VgItZA9zxchOtfZ/IP7/KcLj/hRKNdBkkQWI32iYUEnrCs3WG0wNJns4iKrlAtpyfa0IueWY+o5D1dRpBv89Cpn9F+eLAOJ28DkH5DbA8qTvO7dvsiK3og8i6bYVuAVNQdeLpvBgVbpAv+LFKkq4PChGQEQF/NkU8WMnoaJUxFTA==</ds:SignatureValue>
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>MIIC7TCCAdUCBgFVDdhuVDANBgkqhkiG9w0BAQUFADA6MRQwEgYDVQQDDAtUaGlua0VuZXJneTEUMBIGA1UECgwLVGhpbmtFbmVyZ3kxDDAKBgNVBAYTA1VTQTAeFw0xNjA2MDEyMTIyMTVaFw0xODExMTgyMTIyMTVaMDoxFDASBgNVBAMMC1RoaW5rRW5lcmd5MRQwEgYDVQQKDAtUaGlua0VuZXJneTEMMAoGA1UEBhMDVVNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgk/U0dIwOSCHptZrUTLKQ2aBSkd6ZGRgwaHg/m0c1VkGf6zcPt2gt8L8rkwk6sY8hys80QoLJEup7vsOVIYHbTbdpwBe4b06BWl3OPhSHhyEtlpjJDe8eBEP0tSOfruemV8RBP9EGU6gQzyBN/A7SFtUwfk5n01/8tfKp5UjCWl50M/RyyEmOp3pxoHyY2FXhX+OKmm2q5O2TgK5fdQU+dPQdmQznkGeu4/cVLJUE8/hFSDa9R6mgnUBs4D4avxpSwMTSaIkQPyi3CSHwsL8Wkeb4A0wEgmma+8Xlyf9ZMYbFZLG0+Hl0xWxsF0MP8I79qkZhaGXJZtdjzWS0DeyVwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAlrXLQQBxOZAEar5idaCYG8CpjG8qQx2bdH3bTWZBF3/xezsF7pQ4+i3+9VRNBUI6XqOsJg3DJC+6TgY1HLF7DyR3XMNWPwdAscm0KwiyQgOxYpg+Dt46ooZ57QrBAxfbhxAu2bqVTHgr182xC4Fsmqrr9QJ2azTEPWQoQ34lJ41X2TMvsCD+1ZABy145zRVBjiJcmOrp3sNvWnt5kMJVZ/vjRM1l8EnFP3hiI+cu8vGB45jHBrl87rBGuznt5mEUQcPrVKgOlnv3O2GmiK9V3ZK4l0xLecyLKhNo39sIibwBsU5RUqy9wU0Q1vesbxgE5Wnu1rNY993OpgsGxGtUA</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </ds:Signature>"
            end
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

          encoded_request   = CGI.escape(base64_request.strip)
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
