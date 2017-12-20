use std::io;
use env;
use httpbis;

error_chain! {
	errors {
		// NoErrors
		// ProcessingError
		// MissingDeviceToken
		// MissingTopic
		// MissingPayload
		// InvalidTokenSize
		// InvalidTopicSize
		// InvalidToken
		// Shutdown
		// ProtocolError
		// Unknown
	}

	foreign_links {
		Io(io::Error);
		Env(env::VarError);
		Http2(httpbis::Error);
	}
}
