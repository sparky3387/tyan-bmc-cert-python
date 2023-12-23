use reqwest;

use reqwest::Url;




use std::path::Path;
use clap::Parser;
extern crate json;

// tyan-bmc -- command line tool to install a cert and key in Tyan's BMC
//             all arguments required
#[derive(Parser,Default,Debug)]
#[clap(version, about, long_about = None, setting = clap::AppSettings::DeriveDisplayOrder)]
struct Args {
    /// FQDN or address of BMC
    bmc: String,
    /// BMC username with sufficient rights to update cert
    username: String,
    /// password of user with sufficient rights to update cert
    password: String,
    /// Filename of cert file in pem format
    filename: String,
    /// Filename of key file in pem format
    keyfile: String,
}

fn main() {
    let args = Args::parse();

    let bmc = args.bmc;

    println!("Calling {}...",&bmc);

    let mut builder = reqwest::blocking::Client::builder();
    builder = builder.danger_accept_invalid_certs(true);
    builder = builder.cookie_store(true);
    let client = builder.build().unwrap();

    let authurl = format!("https://{}/api/session",&bmc);
    
    let url = Url::parse(&authurl).unwrap();

    let auth = format!("username={}&password={}",args.username,args.password);

    let bmcref = format!("https://{}", &bmc);

    let result = client
        .post(url)
        .body(auth)
        .header("Connection","keep-alive")
        .header("Accept", "application/json, text/javascript, */*; q=0.01")
        .header("Host",&bmc)
        .header("Origin", &bmcref)
        .header("Referer", &bmcref)
        .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .send();

    match &result {
        Ok(r) => {
            if r.status() != 200 {
                println!("Not authenticated: {:?}", r.status());
                return();
            }}
        Err(e) => {
            println!("Error: {:?}", e);
            return();
        }
    }    

//  println!("{:?}", result);
    let r = result.unwrap();
    let body: String = r.text().unwrap();
//  println!("{:?}", body);
    let data = json::parse(&body).unwrap();
    let csrftoken: String = data["CSRFToken"].to_string();
//  println!("{:?}", csrftoken);
//  println!("-=-=-=-=-=-=-=-=-=-=-=-"); */

/*   
    let url = Url::parse("https://tyan.stowe.network/api/settings/ssl/certificate-info").unwrap();
    let result = client
        .get(url)
  /*      .header("Accept", "application/json, text/javascript, */*; q=0.01")
        .header("Connection","keep-alive")
        .header("Host","tyan.stowe.network")
        .header("Origin", "https://tyan.stowe.network")
        .header("Referer", "https://tyan.stowe.network/")
        .header("X-CSRFTOKEN", &csrftoken)
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Site", "same-origin")
        .header("X-Requested-With", "XMLHttpRequest")
        .send();

    println!("{:?}", result);
    let r = result.unwrap();
    let body: String = r.text().unwrap();
    println!("{:?}", body);
    println!("-=-=-=-=-=-=-=-=-=-=-=-");
    */


    let posturl = format!("https://{}/api/settings/ssl/certificate",&bmc);

    let url = Url::parse(&posturl).unwrap();

    let cert_string: String = std::fs::read_to_string(&args.filename).unwrap();

    let key_string: String = std::fs::read_to_string(&args.keyfile).unwrap();

    let form_filename: String  = Path::new(&args.filename).file_name().unwrap().to_str().unwrap().to_string();
    let form_keyfile: String  = Path::new(&args.keyfile).file_name().unwrap().to_str().unwrap().to_string();

    let cert_part = reqwest::blocking::multipart::Part::text(cert_string)
        .file_name(form_filename)
        .mime_str("application/octet-stream").unwrap();
    
    let key_part = reqwest::blocking::multipart::Part::text(key_string)
        .file_name(form_keyfile)
        .mime_str("application/octet-stream").unwrap();

    let form = reqwest::blocking::multipart::Form::new()
        .part("new_certificate",cert_part)
        .part("new_private_key",key_part);

    let result = client
        .post(url)
        .header("Accept", "application/json, text/javascript, */*; q=0.01")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Host",&bmc)
        .header("Origin", &bmcref)
        .header("Referer", &bmcref)
        .header("X-CSRFTOKEN", &csrftoken)
        .header("X-Requested-With","XMLHttpRequest")
        .multipart(form)
        .send(); 

    match &result {
        Ok(r) => {
            if r.status() != 200 {
                println!("Not authenticated: {:?}", r.status());
                return();
            }}
        Err(e) => {
            println!("Error: {:?}", e);
            return();
        }
    }    

    let r = result.unwrap();
    let body: String = r.text().unwrap();
    let data = json::parse(&body).unwrap();
    let cc: String = data["cc"].to_string();

    if cc == "0" {
        println!("Success");
    } else {
        println!("Unknown failure");
    }
}
