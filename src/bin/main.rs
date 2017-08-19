extern crate futures;
use futures::future::*;

fn main() {
    let f = join_all(vec![
        ok::<u32, u32>(1),
        ok::<u32, u32>(2),
        ok::<u32, u32>(3),
    ]);
    let f = f.map(|x| {
        assert_eq!(x, [1, 2, 3]);
    });

    let f = join_all(vec![
        ok::<u32, u32>(1).boxed(),
        err::<u32, u32>(2).boxed(),
        ok::<u32, u32>(3).boxed(),
    ]);
    let f = f.then(|x| {
        assert_eq!(x, Err(2));
        x
    });
}
