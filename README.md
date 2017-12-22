# Apns using http2

## usage
```
		let auth = Auth::new(
			env::var("APNS_CERT_FILE").unwrap(),
			env::var("APNS_PRIVATE_KEY_FILE").unwrap(),
			env::var("APNS_CA_FILE").unwrap(),
		).unwrap();

		let request = Request::new(
			DeviceToken::from_str(&env::var("APNS_DEVICE_TOKEN").unwrap()).unwrap(),
			Arc::new(json!({
				"action": "warning",
				"title": "wonk",
				"description": "tjusning"
			})),
			None,
			None,
		);
		let client = Client::new(&auth).unwrap();

		client.send(request).wait();
```

# todo

priority and expiration are currently not implemented