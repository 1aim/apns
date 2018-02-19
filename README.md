# Apns using http2

## usage
```rust
let auth = Auth::new(
	env::var("APNS_CERT_FILE").unwrap(),
	env::var("APNS_PRIVATE_KEY_FILE").unwrap(),
	env::var("APNS_CA_FILE").unwrap(),
).unwrap();

let token = DeviceToken::from_str(&env::var("APNS_DEVICE_TOKEN").unwrap()).unwrap();
let payload = json!({
	"action": "warning",
	"title": "wonk",
	"description": "tjusning"
});

let request = Request::new(token, payload, None, None);
let client = Client::new(&auth).unwrap();

client.send(request).wait().unwrap();
```

# Note

Since the `httpbis` crate does not support any non-hacky way of setting up certificates for
the https connection, the auth information is passed to the connection builder in a thread
local.