# Overview

## What

Pomerium is an open-source, identity-aware access proxy.

## Why

Traditional [perimeter](https://www.redbooks.ibm.com/redpapers/pdfs/redp4397.pdf) [security](https://en.wikipedia.org/wiki/Perimeter_Security)has some shortcomings, namely:

- Insider threat is not well addressed and 28% of breaches are [by internal actors](http://www.documentwereld.nl/files/2018/Verizon-DBIR_2018-Main_report.pdf).
- Impenetrable fortress in theory falls in practice; multiple entry points (like VPNs), lots of firewall rules, network segmentation creep.
- Failure to encapsulate a heterogeneous mix of cloud, on-premise, cloud, and multi-cloud environments.
- User's don't like VPNs.

Pomerium attempts to mitigate these shortcomings by adopting the following principles.

- Trust flows from user, device, and context.
- Network location _does not impart trust_. Treat both internal and external networks as completely untrusted.
- Act like you are already breached, because your probably are.
- Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Policy should be dynamic, and built from multiple sources.

## Resources

### Books

- [Zero Trust Networks](http://shop.oreilly.com/product/0636920052265.do) by Gilman and Barth

### Papers

- Forrester [Build Security Into Your Network's DNA: The Zero Trust Network Architecture](http://www.virtualstarmedia.com/downloads/Forrester_zero_trust_DNA.pdf)
- Google BeyondCorp 1 [An overview: "A New Approach to Enterprise Security"](https://research.google.com/pubs/pub43231.html)
- Google BeyondCorp 2 [How Google did it: "Design to Deployment at Google"](https://research.google.com/pubs/pub44860.html)
- Google BeyondCorp 3 [Google's front-end infrastructure: "The Access Proxy"](https://research.google.com/pubs/pub45728.html)
- Google BeyondCorp 4 [Migrating to BeyondCorp: Maintaining Productivity While Improving Security](https://research.google.com/pubs/pub46134.html)
- Google BeyondCorp 5 [The human element: "The User Experience"](https://research.google.com/pubs/pub46366.html)
- Google BeyondCorp 6 [Secure your endpoints: "Building a Healthy Fleet"](https://ai.google/research/pubs/pub47356)

### Posts

- Google [Securing your business and securing your fleet the BeyondCorp way](https://cloud.google.com/blog/products/identity-security/securing-your-business-and-securing-your-fleet-the-beyondcorp-way)
- Google [Preparing for a BeyondCorp world: Understanding your device inventory](https://cloud.google.com/blog/products/identity-security/preparing-beyondcorp-world-understanding-your-device-inventory)
- Google [How BeyondCorp can help businesses be more productive](https://www.blog.google/products/google-cloud/how-beyondcorp-can-help-businesses-be-more-productive/)
- Google [How to use BeyondCorp to ditch your VPN, improve security and go to the cloud](https://www.blog.google/products/google-cloud/how-use-beyondcorp-ditch-your-vpn-improve-security-and-go-cloud/)
- Wall Street Journal [Google Moves Its Corporate Applications to the Internet](https://blogs.wsj.com/cio/2015/05/11/google-moves-its-corporate-applications-to-the-internet/)

### Videos

- [USENIX Enigma 2016 - NSA TAO Chief on Disrupting Nation State Hackers](https://youtu.be/bDJb8WOJYdA?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf)
- [What, Why, and How of Zero Trust Networking](https://youtu.be/eDVHIfVSdIo?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Armon Dadgar, Hashicorp
- [O'Reilly Security 2017 NYC Beyondcorp: Beyond Fortress Security](https://youtu.be/oAvDASLehpY?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Neal Muller, Google
- [Be Ready for BeyondCorp: enterprise identity, perimeters and your application](https://youtu.be/5UiWAlwok1s?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Jason Kent
