# dataflux-pytorch

## Security Research

This package was registered as part of authorized security research for the
**Google Cloud Vulnerability Rewards Program (VRP)**.

It demonstrates a **dependency confusion vulnerability** where the package name
`dataflux-pytorch` is referenced in the GoogleCloudPlatform/gcs-connector-for-pytorch repository but was not
registered on PyPI, allowing an attacker to claim it.

**This is not malicious software.** The package only sends minimal diagnostic
information (hostname, username, public IP) to a callback server to prove
exploitability.

If you received this package unexpectedly, please contact the Google Security team.
