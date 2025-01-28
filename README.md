# tyan-bmc-cert-python

This is another quick-and-dirty command line utility for uploading certs to an AST2500 BMC/IPMI (Python version of mwstowes script).

While the Baseboard Management Controller supports somebody logging in and uploading a cert interactively, this is less than ideal for automation, especially when using [Let's Encrypt certificates](https://letsencrypt.org/), which generally get updated every 60 days or so.

It's pretty straightforward to use:

USAGE:

    tyan-bmc-python --config <FILE>


ARGS:

    --config <FILE>  Filename of key file in pem format

OPTIONS:
    
    -h, --help       Print help information
    
    -V, --version    Print version information`

### Notes

It requires no parameters. It will try to load the config.json from the script directory

It doesn't validate certs, so it should work even if a cert has expired.  On the other hand, it does not have a lot of error checking, so expect pretty messy output if something goes wrong.  It understands when the cert is properly updated; if anything else goes wrong, it'll pretty much
just throw up its hands.

From testing it appears the TYAN BMC at least on my (S8050) version is not sending the intermediate certificate from the fullchain.pem, this means clients (other than web browsers on Windows it appears) require a certificate chain file composed of the ISRG root X1 and what ever intermediate certificate you are using, ill log a case with Mitac/TYAN to see if it can be resolved. Also to note, that the redfish CertificateService.ReplaceCertificate interface only accepts RSA keys up to a maximum of 2048 key length before it will reject, hence why using the web interface. It appears to be a vendor specific limitation not anything to do with redfish.



