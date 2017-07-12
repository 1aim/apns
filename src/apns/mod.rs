use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use openssl;
use openssl::ssl;
use openssl::ssl::SslStream;

use serde_json;

use std::ops::{Range, Index};
use std::net::TcpStream;
use std::io::{Cursor};
use std::path::Path;
use std::vec::Vec;
use std::time;

use num::pow;
use rand::{self, Rng};
use hex::FromHex;

use std::io::Read;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    pub aps: PayloadAPS,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub info: Option<serde_json::Value>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PayloadAPS {
    #[serde(skip_serializing_if = "Option::is_none")]
	pub alert: Option<PayloadAPSAlert>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sound: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub content_available: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub category: Option<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PayloadAPSAlertDictionary {
    #[serde(skip_serializing_if = "Option::is_none")]
	pub title: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub body: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub title_loc_key: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub title_loc_args: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub action_loc_key: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub loc_key: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub loc_args: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub launch_image: Option<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PayloadAPSAlert {
    Plain(String),
	Localized(String, Vec<String>),
	Dictionary(PayloadAPSAlertDictionary)
}


#[allow(dead_code)]
fn hex_to_int(hex: &str) -> u32 {
    let mut total = 0u32;
    let mut n = hex.to_string().len();
    
    for c in hex.chars() {
        n = n - 1;
		match c {
		    '0'...'9' => {
				total += pow(16, n) * ((c as u32) - ('0' as u32));
		    },
		    'a'...'f' => {
				total += pow(16, n) * ((c as u32) - ('a' as u32) + 10);
		    },
		    _ => {
				
		    }
		}
    }
    
    return total;
}

#[allow(dead_code)]
pub fn convert_to_token(binary: &[u8]) -> String {
    let mut token = "".to_string();
    for i in 0..8 {
		let range = Range{start:i*4, end:i*4+4};
		let sub_slice = binary.index(range);
	
		let mut rdr = Cursor::new(sub_slice.to_vec());
		let num = rdr.read_u32::<BigEndian>().unwrap();
	
		token = format!("{}{:x}", token, num);
    }
    return token;
}

#[allow(dead_code)]
pub fn convert_to_timestamp(binary: &[u8]) -> u32 {
    let mut rdr = Cursor::new(binary.to_vec());
    let num = rdr.read_u32::<BigEndian>().unwrap();
    
    return num;
}

pub struct APNS<'a> {
    pub sandbox: bool,
    pub certificate: &'a Path,
    pub private_key: &'a Path,
    pub ca_certificate: &'a Path,
}

impl<'a> APNS<'a> {
    pub fn new(sandbox: bool, cert_file: &'a Path, private_key_file: &'a Path, ca_file: &'a Path) -> APNS<'a> {
		APNS{sandbox: sandbox, certificate: cert_file, private_key: private_key_file, ca_certificate: ca_file}
    }
    
    #[allow(dead_code)]
	pub fn get_feedback(&self) -> Result<Vec<(u32, String)>, Error> {
		let apns_feedback_production = ("feedback.push.apple.com",2196);
		let apns_feedback_development = ("feedback.sandbox.push.apple.com",2196);
        
		let apns_feedback_url = if self.sandbox { apns_feedback_development } else { apns_feedback_production };
		let mut stream = try!(get_ssl_stream(apns_feedback_url, self.certificate, self.private_key, self.ca_certificate));

		let mut tokens: Vec<(u32, String)> = Vec::new();
		let mut read_buffer = [0u8; 38];
        loop {
            match stream.ssl_read(&mut read_buffer) {
                Ok(size) => {
                    if size != 38 {
                        break;
                    }
                },
				Err(e) => {
				    return Err(Error::SslStream(e));
                }
            }
			//println!("feedback read: {:?}",read_buffer);
		    let time_range = Range{start:0, end:4};
		    let time_slice = read_buffer.index(time_range);
		    let time = convert_to_timestamp(time_slice);
    
		    let token_range = Range{start:6, end:38};
		    let token_slice = read_buffer.index(token_range);
			
            let token = convert_to_token(token_slice);
			tokens.push((time, token));
        }

        return Result::Ok(tokens);
    }

    #[allow(dead_code)]
	pub fn send_payload(&self, payload: Payload, device_token: &str) -> Result<u32,Error> {
		use std::str;
		let mut rng = rand::thread_rng();
		let notification_identifier = rng.gen::<u32>();
		println!("payload: {:?}",payload);
		let notification_bytes = get_notification_bytes(payload,notification_identifier, device_token)?;
		let not_str = unsafe { str::from_utf8_unchecked(&notification_bytes) };
		//println!("payload: {}",not_str);
        let apns_url_production = ("gateway.push.apple.com",2195);
        let apns_url_development = ("gateway.sandbox.push.apple.com",2195);
        
        let apns_url = if self.sandbox { apns_url_development } else { apns_url_production };
        
        let ssl_result = get_ssl_stream(apns_url, self.certificate, self.private_key, self.ca_certificate);
        match ssl_result {
            Ok(mut ssls) => {
                if let Err(error) = ssls.ssl_write(&notification_bytes) {
                    println!("ssl_stream write error {:?}", error); 
					return Err(Error::SslStream(error));
                }
				ssls.flush().unwrap();
//				//FIXME: handle errors:
//				//return Ok(notification_identifier);
//				//ssls.get_mut().set_read_timeout(Some(time::Duration::new(0, 100000000))); //10ms
//				println!("num_bytes: {:?}",ssls.ssl().pending());
//				let mut read_buffer = [0u8; 6];
//				let mut read_buffer2 = [0u8; 0];
//				println!("read 1: {:?}",ssls.ssl_read(&mut read_buffer2));
//				println!("num_bytes2: {:?}",ssls.ssl().pending());
//				//let read = ssls.ssl_read(&mut read_buffer);
//				//println!("read: {:?} {:?}",read,read_buffer);
//				let mut res_vec: Vec<u8> = vec![];
//				let res = ssls.read_to_end(&mut res_vec);
//				println!("read_to_end: {:?} {:?}",res,res_vec);
				// Read possible error code response
				if ssls.ssl().pending() == 6 {
                    let mut read_buffer = [0u8; 6];
                    match ssls.ssl_read(&mut read_buffer) {
                        Ok(size) => {
                            for c in read_buffer.iter() {
                                print!("{}", c);
                            }
                            println!("ssl_stream read size {:?}", size);
                        }
                        Err(error) => {
                            println!("ssl_stream read error {:?}", error);
							return Err(Error::SslStream(error));
                        }
                    }
                }
            },
            Err(error) => {
                println!("failed to get_ssl_stream error {:?}", error);
				return Err(error);
            }
        };
		Ok(notification_identifier)
    }
}

fn get_notification_bytes(payload: Payload, identifier: u32, device_token: &str) -> Result<Vec<u8>,Error> {
	let payload_str = json!(payload).to_string();

    let payload_bytes = payload_str.into_bytes();
	let device_token_bytes: Vec<u8> = Vec::from_hex(device_token).unwrap();

    let mut notification_buffer: Vec<u8> = vec![];
    let mut message_buffer: Vec<u8> = vec![];

    // Device token
    let mut device_token_length = vec![];
    let _ = device_token_length.write_u16::<BigEndian>(device_token_bytes.len() as u16);

    message_buffer.push(1u8);
    for s in device_token_length.iter() {
        message_buffer.push(*s);
    }
    for s in device_token_bytes.iter() {
	    message_buffer.push(*s);
	}

    // Payload
	if payload_bytes.len() > 2048 {
	    return Err(Error::PayLoadTooBig());
	}

    let mut payload_length = vec![];
    let _ = payload_length.write_u16::<BigEndian>(payload_bytes.len() as u16);

    message_buffer.push(2u8);
    for s in payload_length.iter() {
        message_buffer.push(*s);
    }
    for s in payload_bytes.iter() {
        message_buffer.push(*s);
    }



    // Notification identifier
    let payload_id = rand::thread_rng().gen();
    let mut payload_id_be = vec![];
    let _ = payload_id_be.write_u32::<BigEndian>(payload_id);

    let mut payload_id_length = vec![];
    let _ = payload_id_length.write_u16::<BigEndian>(payload_id_be.len() as u16);

    message_buffer.push(3u8);
    for s in payload_id_length.iter() {
        message_buffer.push(*s);
    }
    for s in payload_id_be.iter() {
        message_buffer.push(*s);
    }

    //	Expiration date
    let time = match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
        Ok(dur) => dur,
        Err(err) => err.duration(),
    }.as_secs() + 86400;  // expired after one day
    let mut exp_date_be = vec![];
    let _ = exp_date_be.write_u32::<BigEndian>(time as u32);

    let mut exp_date_length = vec![];
    let _ = exp_date_length.write_u16::<BigEndian>(exp_date_be.len() as u16);

    message_buffer.push(4u8);
    for s in exp_date_length.iter() {
        message_buffer.push(*s);
    }
    for s in exp_date_be.iter() {
        message_buffer.push(*s);
    }
	// notification identifier
	let mut notification_identifier_be = vec![];
	let _ = notification_identifier_be.write_u32::<BigEndian>(identifier as u32);
	let mut notification_identifier_length = vec![];
	let _ = notification_identifier_length.write_u16::<BigEndian>(notification_identifier_be.len() as u16);

    message_buffer.push(3u8);
	for s in notification_identifier_length.iter() {
	    message_buffer.push(*s);
	}
	for s in notification_identifier_be.iter() {
	    message_buffer.push(*s);
	}

    // Priority
    let mut priority_length = vec![];
    let _ = priority_length.write_u16::<BigEndian>(1u16);

    message_buffer.push(5u8);
    for s in priority_length.iter() {
        message_buffer.push(*s);
    }
	message_buffer.push(5u8);

    let mut message_buffer_length = vec![];
    let _ = message_buffer_length.write_u32::<BigEndian>(message_buffer.len() as u32);
    
    let command = 2u8;
    notification_buffer.push(command);
    for s in message_buffer_length.iter() {
        notification_buffer.push(*s);
    }
    for s in message_buffer.iter() {
        notification_buffer.push(*s);
    }
	//println!("not buf: {:?}",notification_buffer);
    return Ok(notification_buffer);
}

fn get_ssl_stream((url_host,url_port):(&str,u64), cert_file: &Path, private_key_file: &Path, ca_file: &Path) -> Result<SslStream<TcpStream>, Error> {
	let mut connector_builder = try!(ssl::SslConnectorBuilder::new(ssl::SslMethod::tls()).map_err(|e|Error::SslContext(e)));
	{
	    let context = connector_builder.builder_mut();
		if let Err(error) = context.set_ca_file(ca_file) {
		    println!("set_CA_file error {:?}", error);
			return Err(Error::SslContext(error));
		}
		if let Err(error) = context.set_certificate_file(cert_file, openssl::x509::X509_FILETYPE_PEM) {
		    println!("set_certificate_file error {:?}", error);
			return Err(Error::SslContext(error));
		}
		if let Err(error) = context.set_private_key_file(private_key_file, openssl::x509::X509_FILETYPE_PEM) {
		    println!("set_private_key_file error {:?}", error);
			return Err(Error::SslContext(error));
		}
	}
    let tcp_conn = match TcpStream::connect(format!("{}:{}",url_host,url_port).as_str()) {
		Ok(conn) => { 
			conn 
		},
		Err(error) => {
		    return Err(Error::TcpStream(error));
		}
	};
	let connector = connector_builder.build();
	connector.connect(url_host,tcp_conn).map_err(|e|Error::Handshake(e))
}

/* ERRORS */
quick_error! {
    #[derive(Debug)]
	pub enum Error {
	    Handshake(err: openssl::ssl::HandshakeError<TcpStream>) {from() cause(err)}
		TcpStream(err: ::std::io::Error) { from() cause(err) }
		SslContext(err: openssl::error::ErrorStack) { from() cause(err) }
		SslStream(err: openssl::ssl::Error) { from() cause(err) }
		PayLoadTooBig() {}
	}
}
