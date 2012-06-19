# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "openssl"
require "nokogiri"
require "digest/sha1"

module OmniAuth
  module Strategies
    class SAML

      module XMLSecurity

        class SignedDocument < Nokogiri::XML::Document
          DSIG = "http://www.w3.org/2000/09/xmldsig#"
          EC   = "http://www.w3.org/2001/10/xml-exc-c14n#"

          attr_accessor :signed_element_id

          def initialize
            extract_signed_element_id
          end

          def validate(idp_cert_fingerprint, soft = true, idp_cert = nil, inclusive_namespaces_for_signed_info_canonicalization = nil)
            if idp_cert
              # Use certificate provided in settings
              cert_text = idp_cert.gsub(/^ +/, '')
              base64_cert = Base64.encode64(cert_text)
            else
              # Get certificate from response
              base64_cert = self.at_xpath(".//ds:X509Certificate", { "ds" => DSIG }).text
              cert_text = Base64.decode64(base64_cert)
            end
            cert = OpenSSL::X509::Certificate.new(cert_text)

            # Check certificate matches registered IdP certificate
            fingerprint = Digest::SHA1.hexdigest(cert.to_der)

            if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
              SAML::log :error, "Fingerprint Mismatch"
              return soft ? false : (raise OmniAuth::Strategies::SAML::ValidationError.new("Fingerprint mismatch"))
            end
            validate_doc(cert, soft, inclusive_namespaces_for_signed_info_canonicalization)
          end

          def validate_doc(cert, soft = true, inclusive_namespaces_for_signed_info_canonicalization = nil)
            # Check for inclusive namespaces
            inclusive_namespaces            = []
            inclusive_namespace_element     = self.at_xpath(".//ec:InclusiveNamespaces", { "ec" => EC })
            if inclusive_namespace_element
              prefix_list                   = inclusive_namespace_element.attributes['PrefixList'].value
              inclusive_namespaces          = prefix_list.split(" ")
            end

            # Verify signature
            signed_info_element     = self.at_xpath(".//ds:SignedInfo", { "ds" => DSIG })
            canon_string            = signed_info_element.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive_namespaces_for_signed_info_canonicalization)
            base64_signature        = self.at_xpath(".//ds:SignatureValue", { "ds" => DSIG }).text
            signature               = Base64.decode64(base64_signature)
            if !cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)
              SAML::log :error, "Key Validation Error."
              return soft ? false : (raise OmniAuth::Strategies::SAML::ValidationError.new("Key validation error"))
            end

            # Remove Signature Node (must be done after signature verification)
            sig_element = self.at_xpath(".//ds:Signature", { "ds" => DSIG })
            sig_element.remove

            # Check Digests (must be done after sig_element removal)
            sig_element.xpath(".//ds:Reference", { "ds" => DSIG }).each do |ref|
              uri                     = ref.attributes["URI"].value
              unless uri.nil? || uri.empty?
                hashed_element = self.at_xpath(".//*[@ID='#{uri[1..-1]}']")
              else
                hashed_element = self.at_xpath(".//samlp:Response")
              end
              canon_hashed_element    = hashed_element.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive_namespaces)
              hash                    = Base64.encode64(Digest::SHA1.digest(canon_hashed_element)).chomp
              digest_value            = ref.at_xpath(".//ds:DigestValue", { "ds" => DSIG }).text

              if hash != digest_value
                SAML::log :error, "Digest Mismatch."
                return soft ? false : (raise OmniAuth::Strategies::SAML::ValidationError.new("Digest mismatch"))
              end
            end

            return true
          end

          private

          def extract_signed_element_id
            reference_element       = self.at_xpath("//ds:Signature/ds:SignedInfo/ds:Reference", { "ds" => DSIG })
            self.signed_element_id  = reference_element.attribute("URI").value unless reference_element.nil?
          end
        end
      end

    end
  end
end
