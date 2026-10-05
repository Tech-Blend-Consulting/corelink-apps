# techblend-transit

Transit API client for Tech Blend CoreLink. Standard library only -- no runtime
dependencies in the credential path.

```ruby
require 'transit_client'

client = TransitClient::Client.new(
  transit_url: 'http://127.0.0.1:8200',
  platform_url: 'https://usecorelink.com',
  nhi_id: ENV['NHI_ID']
)

client.bootstrap                        # NHI attestation + background heartbeat
value = client.get_secret('db-password')

watcher = TransitClient::Watcher.new(client, interval: 15)
watcher.watch_secret('db-password') { |v| puts 'rotated' }
watcher.start
```

Authentication is NHI passwordless attestation: under Kubernetes the projected
service account token, otherwise a host fingerprint. No token is stored.
Pass `ca_cert_file:` to pin the origin's CA.
