# nmap-farewell

This tool aims to demonstrate the capabilities of the `nfnetlink_queue` feature of the Linux kernel.

For more in-depth information, you can read [this article](https://www.synacktiv.com/en/publications/automated-network-security-with-rust-detecting-and-blocking-port-scanners).

Before packets are being dropped by the kernel, they are sent to this tool for further processing.
If a remote peer tries to reach too many closed ports on your machine,
it will automatically get banned by inserting a drop statement of its IP address very early in the networking stack
(before any packet defragmentation or connection tracking occurs).

IPs that got banned will be automatically unbanned after a given period of time, this is helpful in case:

- You accidentally lock yourself out of a remote server
- You ban a public IP address that will later be assigned to someone else
- You ban a private IP address that would be a different machine on another LAN (and you suspended your laptop for example)

## Requirements

For this tool to work, you must add the following statement at the end of your nftables input chain:

```
queue num 0-3 fanout
```

And then restart the `nftables` service:

```
sudo systemctl restart nftables
```

## Installation

To install this tool from source, you must have the stable Rust toolchain installed, you can use [rustup](https://rustup.rs/) for that purpose.

Then run the following commands:

```
make
sudo make install
```

## Roadmap

- Leverage the `set` feature of nftables for faster banned IPs lookups instead of adding a new ban rule for each client.
