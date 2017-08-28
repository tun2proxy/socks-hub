extern crate futures;
extern crate tokio_core;
extern crate tokio_io;

use futures::stream::Stream;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;

use futures::future::Future;

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let address = "0.0.0.0:12345".parse().unwrap();
    let listener = TcpListener::bind(&address, &handle).unwrap();

    let server = listener.incoming().for_each(|(_socket, _welcome)| {
        let s = tokio_io::io::write_all(_socket, b"hello world!")
            .map(|_| {
                println!("success!");
            })
            .map_err(|_| {
                println!("err!");
            });

        handle.spawn(s);
        Ok(())
    });

    core.run(server).unwrap();
}
