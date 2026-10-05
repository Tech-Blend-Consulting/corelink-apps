# @techblend/transit

Transit API client for Tech Blend CoreLink. Standard library only -- no runtime
dependencies in the credential path.

```js
const { TransitClient, Watcher } = require('@techblend/transit');

const client = new TransitClient({
  transitUrl: 'http://127.0.0.1:8200',
  platformUrl: 'https://usecorelink.com',
  nhiId: process.env.NHI_ID,
});

await client.bootstrap();               // NHI attestation + background heartbeat
const value = await client.getSecret('db-password');

const watcher = new Watcher(client, 15000);
watcher.watchSecret('db-password', v => console.log('rotated'));
watcher.start();
```

Authentication is NHI passwordless attestation: under Kubernetes the projected
service account token, otherwise a host fingerprint. No token is stored.
Pass `caCertFile` to pin the origin's CA.
