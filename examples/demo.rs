extern crate futures;
extern crate gauthz;
use futures::Future;

use gauthz::{Credentials, Result, Scope, Tokens};

async fn run() -> Result<String> {
    let tokens = Tokens::new(
        Credentials::default().unwrap(),
        vec![Scope::CloudPlatform],
    );
    let access_token = tokens.get().await;
    access_token.map(|t| t.value().to_owned())
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(ok) => println!("{}", ok),
        Err(err) => println!("{}", err),
    }
}
