---
title: Background
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy beyondcorp zero-trust reverse-proxy ztn zta
---

# Background

## History

For years, security has been synonymous with the perimeter security model. This model relies on the strength of its outer defenses. That is, your corporate network is safe so long as your perimeter is impenetrable. Perimeter security typically incorporates tools like firewalls, network segmentation, and VPNs. But perimeter security’s shortcomings have become apparent as:

- Software is shipped differently now. Organizations now deploy code outside their perimeter, in public and private clouds.
- Workforce habits are changing. A majority of the global workforce now works remotely at least one day a week.
- Remote workers want an equivalent user-experience. Traditional tools for internal access like VPNs are clunky and frustrating to use.
- There are now many perimeters to secure and boundaries of the perimeter have become ephemeral and nebulous.

> Most networks [have] big castle walls, hard crunchy outer shell, and soft gooey centers...
>
> [Rob Joyce](https://en.wikipedia.org/wiki/Rob_Joyce) [Chief of Tailored Access Operations](https://en.wikipedia.org/wiki/Tailored_Access_Operations), [National Security Agency @ ENIGMA 2016](https://www.youtube.com/watch?v=bDJb8WOJYdA&feature=youtu.be&t=1627)

Most importantly, the model is just not as secure as we thought. Recent high-profile breaches have demonstrated how difficult it is for even large companies with sophisticated security organizations to avoid a breach. To pick just two of many breaches, consider the Target and Google hacks. In Target's case, hackers circumvented both the physical and network perimeter by [hacking the HVAC system](https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/) which was connected to the internal corporate network from which hackers were then able to move laterally and exfiltrate customer credit card data. In Google's case, they experienced a devastating attack at the hands of the Chinese military known as [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora). After which, Google did a bottom up review of their security posture. The resulting actions from that review would be released as a [series of white papers](https://ai.google/research/pubs/pub43231) called "BeyondCorp" which have since become foundational documents in articulating how and why an organization could move beyond corporate perimeter (BeyondCorp...get it?) based security.

> In reality, there's never one front door; there are many front doors...[and] ... we're not securing a single castle. We're starting to think about securing many different interconnected castles.
>
> [Armon Dadgar, Cofounder of HashiCorp @ PagerDuty Nov 2018](https://www.hashicorp.com/resources/how-zero-trust-networking)

The other side of the security trade-off is operational agility. Perimeter based approaches tend to focus on network segmentation which entails creating virtual or physical boundaries around services that need to communicate. Making those boundaries is increasingly difficult to manage in a world of micro-services, and cloud computing where service communication requirements are constantly in flux.

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
- Treat both internal and external networks as untrusted.
- Act like you are already breached, because you probably are.
- Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Access policy should be dynamic, and built from multiple sources.

To be clear, _perimeter security is not defunct_, nor is zero-trust security a panacea or a single product. Many of the ideas and principles of perimeter security are still relevant and are part of a holistic, and wide-ranging security policy. After all, we still want our castles to have high walls.

## Further reading

The zero-trust security model was first articulated by [John Kindervag](http://www.virtualstarmedia.com/downloads/Forrester_zero_trust_DNA.pdf) in 2010, and by Google in 2011 as a result of the [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora) breach. What follows is a curated list of resources that covers the topic in more depth.

### Government Recommendations

- NIST SP 800-207 (DRAFT) [Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207-draft)
- UK National Cyber Security Centre [Zero trust architecture design principles](https://github.com/ukncsc/zero-trust-architecture/)

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

- Google [How Google adopted BeyondCorp](https://security.googleblog.com/2019/06/how-google-adopted-beyondcorp.html)
- Wall Street Journal [Google Moves Its Corporate Applications to the Internet](https://blogs.wsj.com/cio/2015/05/11/google-moves-its-corporate-applications-to-the-internet/)
- Gitlab's [Blog series](https://about.gitlab.com/blog/tags.html#zero-trust) and their [reddit AMA](https://www.reddit.com/r/netsec/comments/d71p1d/were_a_100_remote_cloudnative_company_and_were/)

### Videos

- [USENIX Enigma 2016 - NSA TAO Chief on Disrupting Nation State Hackers](https://youtu.be/bDJb8WOJYdA?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf)
- [What, Why, and How of Zero Trust Networking](https://youtu.be/eDVHIfVSdIo?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Armon Dadgar, Hashicorp
- [O'Reilly Security 2017 NYC Beyondcorp: Beyond Fortress Security](https://youtu.be/oAvDASLehpY?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Neal Muller, Google
- [Be Ready for BeyondCorp: enterprise identity, perimeters and your application](https://youtu.be/5UiWAlwok1s?list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf) by Jason Kent
