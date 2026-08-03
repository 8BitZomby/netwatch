# netwatch

## Usage

```bash
./build/netwatch <capture.pcap> [--tcp] [--icmp] [--tftp] [--packets] [--all]
```

With no output flags, `netwatch` prints a concise summary of the capture.

Available flags:

- `--tcp` - print detailed TCP flow summaries
- `--icmp` - print detailed ICMP Echo analysis
- `--tftp` - print detailed TFTP transfer summaries
- `--packets` - print detailed information for every decoded packet
- `--all` - print all detailed output sections

Multiple specific flags can be combined. For example:

```bash
./build/netwatch captures/icmp-test.pcap --icmp --packets
```

.pcapng files can also be used

```bash
./build/netwatch captures/icmp-test.pcapng --icmp --packets
```

