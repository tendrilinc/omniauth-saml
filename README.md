# OmniAuth SAML
A tendril-specific flair on generic SAML strategy for OmniAuth. We made changes many moons ago and now we can't upgrade. 

Used here: https://github.com/tendrilinc/energize-fork/blob/80299ac7757e314c85bc6d45fd7e9ab2695b494a/Gemfile#L23

https://github.com/PracticallyGreen/omniauth-saml

## Requirements

* [OmniAuth](http://www.omniauth.org/) 1.1+
* Ruby 1.9.2+

## Usage

Use the SAML strategy as a middleware in your application:

```ruby
require 'omniauth'
use OmniAuth::Strategies::SAML,
  :assertion_consumer_service_url => "consumer_service_url",
  :issuer                         => "issuer",
  :idp_sso_target_url             => "idp_sso_target_url",
  :idp_cert                       => "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----",
  :idp_cert_fingerprint           => "E7:91:B2:E1:...",
  :name_identifier_format         => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  :use_post_binding               => false,
  :requested_authn_context        => false,
  :authn_context_class_ref        => "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
```

or in your Rails application:

in `Gemfile`:

```ruby
gem 'omniauth-saml'
```

and in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :saml,
    :assertion_consumer_service_url => "consumer_service_url",
    :issuer                         => "rails-application",
    :idp_sso_target_url             => "idp_sso_target_url",
    :idp_cert                       => "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----",
    :idp_cert_fingerprint           => "E7:91:B2:E1:...",
    :name_identifier_format         => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    :use_post_binding               => false,
    :requested_authn_context        => false,
    :authn_context_class_ref        => "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
end
```

## Options

* `:assertion_consumer_service_url` - The URL at which the SAML assertion should be
  received. With OmniAuth this is typically `http://example.com/auth/callback`.
  **Required**.

* `:issuer` - The name of your application. Some identity providers might need this
  to establish the identity of the service provider requesting the login. **Required**.

* `:idp_sso_target_url` - The URL to which the authentication request should be sent.
  This would be on the identity provider. **Required**.

* `:idp_cert` - The identity provider's certificate in PEM format. Takes precedence
  over the fingerprint option below. This option or `:idp_cert_fingerprint` must
  be present.

* `:idp_cert_fingerprint` - The SHA1 fingerprint of the certificate, e.g.
  "90:CC:16:F0:8D:...". This is provided from the identity provider when setting up
  the relationship. This option or `:idp_cert` must be present.

* `:name_identifier_format` - Describes the format of the username required by this
  application. If you need the email address, use "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".
  See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for
  other options. Note that the identity provider might not support all options.
  Optional.

* `:use_post_binding` - Whether or not the auth_request should be submitted via POST rather than GET? Optional, default
  is false.

* `:requested_authn_context` - Should the RequestAuthnContext element be included in the request.  Optional, default is
  false. To increase the chance of interoperability this should be set to false. The support for different
  authentication context classes, and the semantics around them may be interpreted differently and may potentially
  cause interoperability problems. If set to true, the participating entities should have a already established
  agreement upon which authentication context classes are available. The authentication context class reference can then
  be set via the `:authn_context_class_ref` option.

* `:authn_context_class_ref` - Request authentication with a specific authentication context class.  Optional.
  Default is "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".  Set to nil or empty to completely
  remove AuthnContextClassRef element from auth request.  Only used when `:requested_authn_context` is true.

## Authors

Authored by Raecoo Cao, Todd W Saxton, Ryan Wilcox, Rajiv Aaron Manglani, and Steven Anderson.

Maintained by [Rajiv Aaron Manglani](http://www.rajivmanglani.com/).

## License

Copyright (c) 2011-2012 [Practically Green, Inc.](http://www.practicallygreen.com/).  
All rights reserved. Released under the MIT license.

Portions Copyright (c) 2007 Sun Microsystems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
