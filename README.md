net-http-oauth
==============


OAuth 1.0 signature algorithms for Net::HTTP requests.


Example usage
-------------

```ruby
require 'net/http'
require 'net/http/oauth'

http = Net::HTTP.new('api.twitter.com', Net::HTTP.https_default_port)
http.use_ssl = true

get_request = Net::HTTP::Get.new('/1.1/statuses/user_timeline.json?screen_name=screen_name')

Net::HTTP::OAuth.sign!(http, get_request, {
  consumer_key: consumer_key,
  consumer_secret: consumer_secret,
  token: oauth_token,
  token_secret: oauth_token_secret
})

puts get_request['Authorization']
```
