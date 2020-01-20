---
title: Background
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy beyondcorp zero-trust reverse-proxy ztn zta
---

# Background

## History

For years, security was synonymous with network security. Firewalls, network segmentation, and VPNs reigned the day. Broadly speaking, that network focused security posture is what people mean today when they talk about the perimeter security model. So-called "impenetrable fortress" security worked well for a period of time when you could reasonably expect your network perimeter to correspond to an actual physical perimeters, users, devices, and servers. But as teams, applications, workloads, and users became more ephemeral and distributed, the shortcomings of perimeter based security have become more apparent in terms of both operational costs and security breaches.

> Most networks [have] big castle walls, hard crunchy outer shell, and soft gooey centers...
>
> [Rob Joyce](https://en.wikipedia.org/wiki/Rob_Joyce) [Chief of Tailored Access Operations](https://en.wikipedia.org/wiki/Tailored_Access_Operations), [National Security Agency @ ENIGMA 2016](https://www.youtube.com/watch?v=bDJb8WOJYdA&feature=youtu.be&t=1627)

There's no such thing as perfect security. Many recent high-profile breaches have demonstrated just how difficult it is for even large companies with sophisticated security organizations to avoid a breach. To pick just two of many possible breaches that epitomize the shortcomings of perimeter security, consider the Target and Google hacks. In Target's case, hackers circumvented both the physical and network perimeter by [hacking the HVAC system](https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/) which was connected to the internal corporate network from which hackers were then able  to move laterally and exfiltrate customer credit card data. In Google's case, they experienced a devastating attack at the hands of the Chinese military known as [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora). After which, Google did a bottom up review of their security posture. The resulting actions from that review would be released as a [series of white papers](https://ai.google/research/pubs/pub43231) called "BeyondCorp" which have since become foundational documents in articulating how and why an organization could move beyond corporate perimeter (BeyondCorp...get it?) based security.

> In reality, there's never one front door; there are many front doors...[and] ... we're not securing a single castle. We're starting to think about securing many different interconnected castles.
>
> [Armon Dadgar, Cofounder of HashiCorp @ PagerDuty Nov 2018](https://www.hashicorp.com/resources/how-zero-trust-networking)

The other side of the security trade-off is operational agility. Perimeter based approaches tend to focus on network segmentation which entails creating virtual or physical boundaries around services that need to communicate. Making those boundaries is increasingly difficult to manage in a world of microservices, and cloud computing where service communication requirements are constantly in flux.

In theory, an organization could "micro/nano/pico-segment" each and every layer of an application stack to ensure appropriate access controls. However, in practice, operators are usually pulled in the direction of one of two extremes. That is, either a very precise boundary that is high-touch, time-consuming to manage, and error prone. Or that of a more lax boundary that may entail more risk but is less time consuming to update, manage and less prone to break.

### Gaps in the perimeter

In summary, perimeter based security suffers from the following shortcomings:

- Perimeter security largely ignores the insider threat.
- The "impenetrable fortress" model fails in practice even for the most sophisticated of security organizations.
- Network segmentation is a time-consuming, and difficult to get exactly right mechanism for ensuring secure communication.
- Even just defining what the network perimeter is is an increasingly difficult proposition in a remote-work, BYOD, multi-cloud world. Most organizations are a heterogeneous mix of clouds, servers, devices, and organizational units.
- VPNs are often misused and exacerbate the issue by opening yet another door into your network organization.

### Zero-trust, security behind the gates

[Zero-trust](https://ldapwiki.com/wiki/Zero%20Trust) instead attempts to mitigate these shortcomings by adopting the following principles:

- Trust flows from identity, device-state, and context; not network location.
- Treat both internal and external networks as completely untrusted. Mutually authenticated encryption is used instead of network segmentation.
- Act like you are already breached, because you probably are. An attacker could be anyone, and anywhere on your network.
- Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Access policy should be dynamic, and built from multiple sources.

To be clear, perimeter security is not defunct, nor is zero-trust security a panacea or a single product. Many of the ideas and principles of perimeter security are still relevant and are part of a holistic, and wide-ranging security policy. After all, we still want our castles to have high walls.

### Where Pomerium Fits

So to put all this back in context, before zero-trust tools like Pomerium existed, access to internal applications were gated by whether a user was on the corporate network or not. Trust flowed through and was anchored to the security of the perimeter. For all the reasons discussed above, this has turned to be a lacking security model. In contrast, Pomerium adopts the zero-trust stance and uses identity, device-state, and context compared against a single-source of rich authorization policy as the basis for delegating access to an internal resource. All Pomerium communication is mutually authenticated and encrypted, there is no trust belied to internal vs external network.

## Further reading

Pomerium was inspired by the security model articulated by [John Kindervag](http://www.virtualstarmedia.com/downloads/Forrester_zero_trust_DNA.pdf) in 2010, and by Google in 2011 as a result of the [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora) breach. What follows is a curated list of books, papers, posts, and videos that covers the topic in more depth.

### Books

- ⭐[Zero Trust Networks](http://shop.oreilly.com/product/0636920052265.do) by Gilman and Barth

### Papers

- NIST SP 800-207 [Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207-draft)
- Forrester [Build Security Into Your Network's DNA: The Zero Trust Network Architecture](http://www.virtualstarmedia.com/downloads/Forrester_zero_trust_DNA.pdf)
- ⭐️Google BeyondCorp 1 [An overview: "A New Approach to Enterprise Security"](https://research.google.com/pubs/pub43231.html)
- Google BeyondCorp 2 [How Google did it: "Design to Deployment at Google"](https://research.google.com/pubs/pub44860.html)
- ⭐️Google BeyondCorp 3 [Google's front-end infrastructure: "The Access Proxy"](https://research.google.com/pubs/pub45728.html)
- Google BeyondCorp 4 [Migrating to BeyondCorp: Maintaining Productivity While Improving Security](https://research.google.com/pubs/pub46134.html)
- Google BeyondCorp 5 [The human element: "The User Experience"](https://research.google.com/pubs/pub46366.html)
- Google BeyondCorp 6 [Secure your endpoints: "Building a Healthy Fleet"](https://ai.google/research/pubs/pub47356)

### Posts

- Google [How Google adopted BeyondCorp](https://security.googleblog.com/2019/06/how-google-adopted-beyondcorp.html)
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
- ⭐️ [OAuth 2.0 and OpenID Connect (in plain English)](https://www.youtube.com/watch?v=996OiexHze0) by Nate Barbettini
