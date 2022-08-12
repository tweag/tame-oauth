use tame_oauth::gcp::*;

// By passing through reqwest, turn a http::Request into a http::Response.
async fn make_request(request: http::Request<Vec<u8>>) -> http::Response<String> {
    let client = reqwest::Client::new();
    let (parts, body) = request.into_parts();
    let uri = parts.uri.to_string();

    // This will always be a POST, but for completeness sake...
    let builder = match parts.method {
        http::Method::GET => client.get(&uri),
        http::Method::POST => client.post(&uri),
        http::Method::DELETE => client.delete(&uri),
        http::Method::PUT => client.put(&uri),
        method => unimplemented!("{} not implemented", method),
    };

    // Build the full request from the headers and body that were
    // passed to you, without modifying them.
    let request = builder.headers(parts.headers).body(body).build().unwrap();

    // Send the actual request
    let response = client.execute(request).await.unwrap();

    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());

    let headers = builder.headers_mut().unwrap();

    // Unfortunately http doesn't expose a way to just use
    // an existing HeaderMap, so we have to copy them :(
    headers.extend(
        response
            .headers()
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );

    let buffer = response.text().await.unwrap();
    builder.body(buffer).unwrap()
}

// This example impersonates a service account by getting the default user
// credentials (which should work as long as you have done
// `gcloud auth application-default login` recently) and then using that user
// to impersonate the service email given as the first command line parameter.
#[tokio::main]
async fn main() {
    let svc_email = std::env::args().skip(1).next().unwrap();
    let scopes: Vec<_> = std::env::args().skip(2).collect();

    let provider = TokenProviderWrapper::get_default_provider()
        .expect("unable to read default token provider")
        .expect("unable to find default token provider");

    if provider.kind() != "End User" {
        println!("Didn't get user credentials: got {}", provider.kind());
        return;
    }

    // Attempt to get a token, since we have never used this accessor
    // before, it's guaranteed that we will need to make an HTTPS
    // request to the token provider to retrieve a token. This
    // will also happen if we want to get a token for a different set
    // of scopes, or if the token has expired.
    match provider.get_token(&scopes).unwrap() {
        TokenOrRequest::Request {
            // This is an http::Request that we can use to build
            // a client request for whichever HTTP client implementation
            // you wish to use
            request,
            scope_hash,
            ..
        } => {
            let response = make_request(request).await;

            let tok = provider
                .parse_token_response(scope_hash, response)
                .expect("invalid token response");

            println!("Got an end user token!");

            // Now, use this token to impersonate a service account.
            let info = ImpersonatedAccountInfo {
                user_token: tok,
                service_account_email: svc_email,
            };

            let im = ImpersonatedAccountProvider::new(info);
            match im.get_token(&scopes).unwrap() {
                TokenOrRequest::Request {
                    // This is an http::Request that we can use to build
                    // a client request for whichever HTTP client implementation
                    // you wish to use
                    request,
                    scope_hash,
                    ..
                } => {
                    let response = make_request(request).await;
                    let tok = im
                        .parse_token_response(scope_hash, response)
                        .expect("invalid im response");
                    println!("we were able to impersonate the requested service!");
                    dbg!(tok);
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}
