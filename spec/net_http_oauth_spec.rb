require 'minitest/autorun'

require_relative '../lib/net/http/oauth'

describe 'Net::HTTP::OAuth' do
  describe 'sign bang method' do
    it 'adds signs the given http request and adds an oauth authorization header' do
      http = Net::HTTP.new('example.com', Net::HTTP.http_default_port)

      request = Net::HTTP::Get.new('/?n=v')

      Net::HTTP::OAuth.sign!(http, request, {consumer_key: 'ck', consumer_secret: 'cs'})

      authorization = request['Authorization']
      authorization.must_match(/\AOAuth /)
      authorization.must_match(/\boauth_version="1.0"/)
      authorization.must_match(/\boauth_nonce="[^"]+"/)
      authorization.must_match(/\boauth_timestamp="\d+"/)
      authorization.must_match(/\boauth_signature_method="HMAC-SHA1"/)
      authorization.must_match(/\boauth_consumer_key="ck"/)
      authorization.must_match(/\boauth_signature="[^"]+"/)
    end
  end

  describe 'plaintext_signature method' do
    it 'returns the encoded consumer secret and token secret' do
      # cf. http://oauth.net/core/1.0/#rfc.section.9.4.1

      consumer_secret = 'djr9rjt0jd78jf88'

      Net::HTTP::OAuth.plaintext_signature(consumer_secret, 'jjd999tj88uiths3').must_equal('djr9rjt0jd78jf88&jjd999tj88uiths3')

      Net::HTTP::OAuth.plaintext_signature(consumer_secret, 'jjd99$tj88uiths3').must_equal('djr9rjt0jd78jf88&jjd99%24tj88uiths3')

      Net::HTTP::OAuth.plaintext_signature(consumer_secret, nil).must_equal('djr9rjt0jd78jf88&')
    end
  end

  describe 'hmac_sha1_signature method' do
    it 'returns the base64 encoded hmac sha1 digest of the given base string' do
      # cf. http://wiki.oauth.net/TestCases

      Net::HTTP::OAuth.hmac_sha1_signature('bs', 'cs', nil).must_equal('egQqG5AJep5sJ7anhXju1unge2I=')

      Net::HTTP::OAuth.hmac_sha1_signature('bs', 'cs', 'ts').must_equal('VZVjXceV7JgPq/dOTnNmEfO0Fv8=')

      base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'

      Net::HTTP::OAuth.hmac_sha1_signature(base_string, 'kd94hf93k423kf44', 'pfkkdhi9sl3r4s00').must_equal('tR3+Ty81lMeYAr/Fid0kMTYa/WM=')
    end
  end

  describe 'rsa_sha1_signature method' do
    it 'returns the base64 encoded rsa sha1 signature of the given base string' do
      key = File.expand_path(File.join(File.dirname(__FILE__), 'rsa_sha1_private_key.pem'))

      base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacaction.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3D13917289812797014437%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1196666512%26oauth_version%3D1.0%26size%3Doriginal'

      signature = 'jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE='

      Net::HTTP::OAuth.rsa_sha1_signature(base_string, key).must_equal(signature)
    end
  end

  describe 'signature_base_string method' do
    it 'returns the encoded and concatenated request components' do
      http = Net::HTTP.new('example.com', Net::HTTP.http_default_port)

      request = Net::HTTP::Get.new('/?n=v')

      Net::HTTP::OAuth.signature_base_string(http, request).must_equal('GET&http%3A%2F%2Fexample.com%2F&n%3Dv')
    end

    it 'correctly encodes the example in appendix 2 of the 1.0a spec' do
      # cf. http://oauth.net/core/1.0a/#rfc.section.A.2

      http = Net::HTTP.new('photos.example.net', Net::HTTP.https_default_port)

      request = Net::HTTP::Post.new('/request_token')

      params = {
        'oauth_version' => '1.0',
        'oauth_consumer_key' => 'dpf43f3p2l4k3l03',
        'oauth_timestamp' => '1191242090',
        'oauth_nonce' => 'hsu94j3884jdopsl',
        'oauth_signature_method' => 'PLAINTEXT'
      }

      base_string = 'POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0'

      Net::HTTP::OAuth.signature_base_string(http, request, params).must_equal(base_string)
    end

    it 'correctly encodes the example in appendix 5 of the 1.0a spec' do
      # cf. http://oauth.net/core/1.0a/#rfc.section.A.5.1

      http = Net::HTTP.new('photos.example.net', Net::HTTP.http_default_port)

      request = Net::HTTP::Get.new('/photos?file=vacation.jpg&size=original')

      params = {
        'oauth_version' => '1.0',
        'oauth_consumer_key' => 'dpf43f3p2l4k3l03',
        'oauth_token' => 'nnch734d00sl2jdk',
        'oauth_timestamp' => '1191242096',
        'oauth_nonce' => 'kllo9940pd9333jh',
        'oauth_signature_method' => 'HMAC-SHA1'
      }

      base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'

      Net::HTTP::OAuth.signature_base_string(http, request, params).must_equal(base_string)
    end

    it 'correctly encodes the example in section 3 of the rfc' do
      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.1

      http = Net::HTTP.new('example.com', Net::HTTP.http_default_port)

      request = Net::HTTP::Post.new('/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b' + '&c2=&a3=2%20q')
      # TODO: request = Net::HTTP::Post.new('/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b')
      # TODO: request.body = 'c2&a3=2+q'

      params = {
        'oauth_consumer_key' => '9djdj82h48djs9d2',
        'oauth_token' => 'kkk9d7dh3k39sjv7',
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_timestamp' => '137131201',
        'oauth_nonce' => '7d8f3e4a'
      }

      base_string = 'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7'

      Net::HTTP::OAuth.signature_base_string(http, request, params).must_equal(base_string)
    end
  end

  describe 'normalized_request_uri method' do
    it 'excludes the port if it is the default port for the scheme' do
      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.2

      http = Net::HTTP.new('EXAMPLE.COM', Net::HTTP.http_default_port)

      request = Net::HTTP::Get.new('/r%20v/X?id=123')

      Net::HTTP::OAuth.normalized_request_uri(http, request).must_equal('http://example.com/r%20v/X')
    end

    it 'includes the port if it is not the default port for the scheme' do
      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.2

      http = Net::HTTP.new('www.example.net', 8080)
      http.use_ssl = true

      request = Net::HTTP::Get.new('/?q=1')

      Net::HTTP::OAuth.normalized_request_uri(http, request).must_equal('https://www.example.net:8080/')
    end
  end
end
