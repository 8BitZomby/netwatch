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
- `--port <1-65535>` - filter packets where either the source or destination port matches the specified port
- `--src-port <1-65535>` - filter packets where the source port matches the specified port
- `--dst-port <1-65535>` - filter packets where the destination port matches the specified port

Multiple specific flags can be combined. For example:

```bash
./build/netwatch captures/icmp-test.pcap --icmp --packets
```

.pcapng files can also be used

```bash
./build/netwatch captures/icmp-test.pcapng --icmp --packets
```

```bash
./built/netwatch captures/shark1.pcapng --tcp --port 80
```
