# actix-web-middleware-slack
actix-web middleware for [Verifying requests from Slack](https://api.slack.com/authentication/verifying-requests-from-slack)

## Installation

```
[dependencies]
actix-web-middleware-slack = <version>
```

## Quick Start

```rust
use actix_web::middleware::{Logger, Slack};
use actix_web::{App, HttpServer, web};
use actix_web_middleware_slack::Slack;

#[tokio::main]
async fn main() {
    // https://api.slack.com/authentication/verifying-requests-from-slack#verifying-requests-from-slack-using-signing-secrets__app-management-updates
    let server = HttpServer::new(move || {
        let signing_secret = "Signing Secret";
        App::new()
            .wrap(Slack::new(signing_secret))
    }).bind(("0.0.0.0", 8090)).unwrap().run();
    server.await;
}
```

## License
This project is licensed under the [MIT license](./LICENCE).

## Contributing
Contributions are welcome.
1. Fork this repository.
2. Make changes, commit to your fork.
3. Send a pull request with your changes.
4. Confirm the success of CI.
