# envelope-encryption-rusty-demo

Small *Envelope Encryption* demo based on the unikernel [RustyHermit](https://github.com/hermitcore/libhermit-rs).

Please read the README of [RustyHermit](https://github.com/hermitcore/libhermit-rs) for more information.


## Requirements

* [`rustup`](https://www.rust-lang.org/tools/install)
* [NASM](https://nasm.us/) (only for x86_64)
* [QEMU](https://www.qemu.org/) for running the application


## Usage

## Init and update submodule
```
$ git submodule update --init
```

### Build the Bootloader

```
$ cd loader
$ cargo xtask build --arch x86_64 --release
```


### Build the Hermit Application

``` 
$ cargo build \
    -Zbuild-std=core,alloc,std,panic_abort \
    -Zbuild-std-features=compiler-builtins-mem \
    --target x86_64-unknown-hermit \
    --release
```


### Run the Application in QEMU

```
$ qemu-system-x86_64 \
    -cpu qemu64,apic,fsgsbase,fxsr,rdrand,rdtscp,xsave,xsaveopt \
    -smp 1 -m 64M \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -display none -serial stdio \
    -kernel loader/target/x86_64/release/rusty-loader \
    -initrd target/x86_64-unknown-hermit/release/hello_world
```


## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
