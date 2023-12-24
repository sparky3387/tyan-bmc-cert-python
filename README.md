# tyan-bmc-cert

This is a quick-and-dirty command line utility for uploading certs to an AST2500 BMC/IPMI.

While the Baseboard Management Controller supports somebody logging in and uploading a cert interactively, this is less than ideal for automation, especially when using [Let's Encrypt certificates](https://letsencrypt.org/), which generally get updated every 60 days or so.

It's pretty straightforward to use:

USAGE:

    tyan-bmc <BMC> <USERNAME> <PASSWORD> <FILENAME> <KEYFILE>`


ARGS:

    <BMC>         FQDN or address of BMC

    <USERNAME>    BMC username with sufficient rights to update cert
    
    <PASSWORD>    password of user with sufficient rights to update cert
    
    <FILENAME>    Filename of cert file in pem format
    
    <KEYFILE>     Filename of key file in pem format

OPTIONS:
    
    -h, --help       Print help information
    
    -V, --version    Print version information`

### Notes

It requires all five parameters.

It doesn't validate certs, so it should work even if a cert has expired.  On the other hand, it does not have a lot of error checking, so expect pretty messy output if something goes wrong.  It understands when the cert is properly updated; if anything else goes wrong, it'll pretty much
just throw up its hands.

Yes, it currently expects the password right on the command line.  This isn't particularly hard to fix, but I haven't yet bothered.
