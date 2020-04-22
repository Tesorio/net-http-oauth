require 'net/http'
require 'openssl'
require 'base64'

module Net
  class HTTP
    module OAuth
      def self.sign!(http, request, options = {})
        consumer_secret = options.fetch(:consumer_secret)

        signature_method = options.fetch(:signature_method) { 'HMAC-SHA1' }

        token_secret = options[:token_secret]

        params = {
          oauth_version: '1.0',
          oauth_nonce: generate_nonce,
          oauth_timestamp: Time.now.to_i,
          oauth_signature_method: signature_method,
          oauth_consumer_key: options.fetch(:consumer_key)
        }

        params[:oauth_token] = options[:token] if options[:token]

        params[:oauth_signature] = case signature_method
        when 'PLAINTEXT'
          plaintext_signature(consumer_secret, token_secret)
        when 'HMAC-SHA1'
          hmac_sha1_signature(signature_base_string(http, request, params), consumer_secret, token_secret)
        when 'RSA-SHA1'
          rsa_sha1_signature(signature_base_string(http, request, params), consumer_secret)
        else
          raise "error: signature method not supported: #{signature_method}"
        end

        request['Authorization'] = authorization_header(params)
      end

      def self.plaintext_signature(consumer_secret, token_secret)
        encode(consumer_secret, token_secret)
      end

      def self.hmac_sha1_signature(base_string, consumer_secret, token_secret)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, encode(consumer_secret, token_secret), base_string))
      end

      def self.rsa_sha1_signature(base_string, consumer_secret)
        Base64.strict_encode64(private_key(consumer_secret).sign(OpenSSL::Digest::SHA1.new, base_string))
      end

      def self.signature_base_string(http, request, params = {})
        encoded_params = params_encode(params_array(request) + params_array(params))

        encode(request.method, normalized_request_uri(http, request), encoded_params)
      end

      def self.normalized_request_uri(http, request)
        if http.port == Net::HTTP.default_port
          scheme, port = :http, nil
        elsif http.port == Net::HTTP.https_default_port
          scheme, port = :https, nil
        elsif http.use_ssl?
          scheme, port = :https, http.port
        else
          scheme, port = :http, http.port
        end

        uri = "#{scheme}://#{http.address.downcase}"
        uri += ":#{port}" if port
        uri += request.path.split('?').first
        uri
      end

      private

      def self.private_key(object)
        OpenSSL::PKey::RSA === object ? object : OpenSSL::PKey::RSA.new(IO.read(object))
      end

      def self.authorization_header(params)
        'OAuth ' + params.map { |k, v| "#{percent_encode(k)}=\"#{percent_encode(v)}\"" }.join(', ')
      end

      def self.generate_nonce
        Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32))
      end

      def self.params_array(object)
        case object
        when Array then return object
        when Hash then return object.to_a
        when Net::HTTPRequest
          tmp = object.path.split('?')
          tmp[1] ? params_decode(tmp[1]) : []
        else
          raise "error: cannot convert #{object.class} object to params array"
        end
      end

      def self.params_decode(string)
        string.split('&').each_with_object([]) do |param, array|
          k, v = *param.split('=')

          array << [percent_decode(k), v && percent_decode(v)]
        end
      end

      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
      def self.params_encode(params)
        params.map { |k, v| [percent_encode(k), percent_encode(v)] }.sort.map { |k, v| "#{k}=#{v}" }.join('&')
      end

      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.1
      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.4
      def self.encode(*components)
        components.map { |component| percent_encode(component) }.join('&')
      end

      # cf. http://tools.ietf.org/html/rfc5849#section-3.6
      def self.percent_encode(input)
        input.to_s.gsub(/([^A-Za-z0-9\-_\.~])/) { '%' + $1.ord.to_s(16).upcase }
      end

      def self.percent_decode(input)
        input.to_s.gsub(/%([a-fA-F0-9]{2})/) { $1.to_i(16).chr }
      end
    end
  end
end
