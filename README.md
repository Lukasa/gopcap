# gopcap

gopcap is a pure Go implementation of the
[pcap file format](http://wiki.wireshark.org/Development/LibpcapFileFormat).
Pcap is the standard open-source packet capture format, and is defined by the
[libpcap](http://wiki.wireshark.org/libpcap) C library.

## Features

- Fully synchronous API that is easy to make asynchronous.
- Efficient with memory use.
- No external dependencies.

## Contributing

gopcap welcomes contributions, both bug fixes and new features (though the
opportunity for new features is obviously fairly limited!). Any feature request
should strongly consider the implications for the API. API clarity is valued
above new features, so any feature that complicates the API must add
significant value to the library to be accepted.

If you'd like to contribute, do the following:

1. Check that your idea hasn't been proposed already, by checking **both open
   and closed** issues on GitHub.
2. Fork the repository from GitHub and make your changes.
3. Where possible, write a test that reproduces the bug and check that it
   passes after your changes have been made.
4. Send a Pull Request. Don't forget to add yourself to the AUTHORS file.

## License

This PCAP parsing library is available under
[the MIT license](http://opensource.org/licenses/MIT). You are free to use this
library, copy it, modify it, publish it, sell it, whatever. For more
information see the enclosed `LICENSE` file.
