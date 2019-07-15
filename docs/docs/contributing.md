---
title: Contributing
description: >-
  This document describes how you can find issues to work on, setup Pomerium
  locally for development, and get help when you are stuck.
---

# Contributing to Pomerium

Thanks for your interest in contributing to Pomerium! We welcome all contributions, from new features to documentation updates. This document describes how you can find issues to work on, setup Pomerium locally for development, and get help when you are stuck.

## Contributing code

You can have a direct impact on the project by helping with its code. To contribute code to Pomerium, open a [pull request](https://github.com/pomerium/pomerium/pulls) (PR). If you're new to our community, that's okay: **we gladly welcome pull requests from anyone, regardless of your native language or coding experience.**

We hold contributions to a high standard for quality :bowtie:, so don't be surprised if we ask for revisions--even if it seems small or insignificant. Please don't take it personally. :wink: If your change is on the right track, we can guide you to make it mergable.

Here are some of the expectations we have of contributors:

- If your change is more than just a minor alteration, **open an issue to propose your change first.** This way we can avoid confusion, coordinate what everyone is working on, and ensure that changes are in-line with the project's goals and the best interests of its users. If there's already an issue about it, comment on the existing issue to claim it.

- **Keep pull requests small.** Smaller PRs are more likely to be merged because they are easier to review! We might ask you to break up large PRs into smaller ones. [An example of what we DON'T do.](https://twitter.com/iamdevloper/status/397664295875805184)

- **Keep related commits together in a PR.** We do want pull requests to be small, but you should also keep multiple related commits in the same PR if they rely on each other.

- **Write tests.** Tests are essential! Written properly, they ensure your change works, and that other changes in the future won't break your change. CI checks should pass.

- **Benchmarks should be included for optimizations.** Optimizations sometimes make code harder to read or have changes that are less than obvious. They should be proven with benchmarks or profiling.

- **[Squash](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html) insignificant commits.** Every commit should be significant. Commits which merely rewrite a comment or fix a typo can be combined into another commit that has more substance. Interactive rebase can do this, or a simpler way is `git reset --soft <diverging-commit>` then `git commit -s`.

- **Own your contributions.** Pomerium is a growing project, and it's much better when individual contributors help maintain their change after it is merged.

- **Use comments properly.** We expect good godoc comments for package-level functions, types, and values. Comments are also useful whenever the purpose for a line of code is not obvious.

- **Recommended reading**

  - [CodeReviewComments](https://github.com/golang/go/wiki/CodeReviewComments) for an idea of what we look for in good, clean Go code
  - [Linus Torvalds describes a good commit message](https://gist.github.com/matthewhudson/1475276)
  - [Best Practices for Maintainers](https://opensource.guide/best-practices/)
  - [Shrinking Code Review](https://alexgaynor.net/2015/dec/29/shrinking-code-review/)

## Getting help using Pomerium

If you have a question about using Pomerium, [join our slack channel](http://slack.pomerium.io/)! There will be more people there who can help you than just the Pomerium developers who follow our issue tracker. Issues are not the place for usage questions.

## Reporting bugs

Like every software, Pomerium has its flaws. If you find one, [search the issues](https://github.com/pomerium/pomerium/issues) to see if it has already been reported. If not, [open a new issue](https://github.com/pomerium/pomerium/issues/new) and describe the bug, and somebody will look into it! (This repository is only for Pomerium, not plugins.)

**You can help stop bugs in their tracks!** Speed up the patch by identifying the bug in the code. This can sometimes be done by adding `fmt.Println()` statements (or similar) in relevant code paths to narrow down where the problem may be. It's a good way to [introduce yourself to the Go language](https://tour.golang.org), too.

Please follow the issue template so we have all the needed information. We need to be able to repeat the bug using your instructions. Please simplify the issue as much as possible. The burden is on you to convince us that it is actually a bug in Pomerium. This is easiest to do when you write clear, concise instructions so we can reproduce the behavior (even if it seems obvious). The more detailed and specific you are, the faster we will be able to help you!

We suggest reading [How to Report Bugs Effectively](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

Please be kind. :smile: Remember that Pomerium comes at no cost to you, and you're getting free support when we fix your issues. If we helped you, please consider helping someone else!

## Suggesting features

First, [search to see if your feature has already been requested](https://github.com/pomerium/pomerium/issues). If it has, you can add a :+1: reaction to vote for it. If your feature idea is new, open an issue to request the feature. You don't have to follow the bug template for feature requests. Please describe your idea thoroughly so that we know how to implement it! Really vague requests may not be helpful or actionable and without clarification will have to be closed.

While we really do value your requests and implement many of them, not all features are a good fit for Pomerium. But if a feature is not in the best interest of the Pomerium project or its users in general, we may politely decline to implement it into Pomerium core.

## Improving documentation

Pomeriums's documentation is available at <https://www.pomerium.io>. If you would like to make a fix to the docs, please submit an issue here describing the change to make.

## Responsible Disclosure

We deeply appreciate any effort to discover and disclose security vulnerabilities responsibly.

If you would like to report a vulnerability, or have any security concerns, please e-mail info@pomerium.io or reach out to me on [keybase](https://keybase.io/bdesimone) .

## Developers Guide

The following guide assumes you do _not_ want to expose your development server to the public internet and instead want to do everything, with the exception of identity provider callbacks, locally.

If you are comfortable with a public development configuration, see the Synology quick-start which covers how to set up your network, domain, and retrieve wild-card certificates from LetsEncrypt, the only difference being you would route traffic to your local development machine instead of the docker image.

### Domains

Publicly resolvable domains are central in how pomerium works. For local development, we'll have to do some additional configuration to mock that public workflow on our local machine.

### Pick an identity provider friendly domain name

Though typically you would want to use one of the TLDs specified by [RFC-2606](http://tools.ietf.org/html/rfc2606) for testing, unfortunately, google explicitly does not support oauth calls to test domains. As such, it's recommended to use a domain you control using a wildcard-subdomain that you know will not be used.

If you do not control a domain, you can use `*.localhost.pomerium.io` which I've established for this use Plus, if you _do_ have internet access, this domain already has a [public A record](https://en.wikipedia.org/wiki/List_of_DNS_record_types) pointing to localhost.

### Wildcard domain resolution with `dnsmasq`

If you are on a plane (for example), you may not be able to access public DNS. Unfortunately, `/etc/hosts` does not support wildcard domains and would require you specifying a new entry for each pomerium managed route. The workaround is to use [dnsmasq](https://en.wikipedia.org/wiki/Dnsmasq) locally which _does_ support local resolution of wildcard domains.

#### OSX

1. Install `brew update && brew install dnsmasq`
2. Edit `/usr/local/etc/dnsmasq.conf` to tell dnsmasq to resolve your test domains.

  ```bash
  echo 'address=/.localhost.pomerium.io/127.0.0.1' > $(brew --prefix)/etc/dnsmasq.conf
  ```

  ```bash
  sudo mkdir -pv /etc/resolver
  sudo bash -c 'echo "nameserver 127.0.0.1" > /etc/resolver/localhost.pomerium.io'
  ```

3. Restart `dnsmasq`

  ```bash
  sudo brew services restart dnsmasq
  ```

4. Tell OSX to use `127.0.0.1` as a the primary DNS resolver (followed by whatever public DNS you are using). ![osx dns resolution](./local-development/local-development-osx-dns.png)

### Locally trusted wildcard certificates

In production, we'd use a public certificate authority such as LetsEncrypt. For local development, enter [mkcert](https://mkcert.dev/) which is a "simple zero-config tool to make locally trusted development certificates with any names you'd like."

1. Install `mkcert`.

  ```bash
  go get -u github.com/FiloSottile/mkcert
  ```

2. Bootstrap `mkcert`'s root certificate into your operating system's trust store.

  ```bash
  mkcert -install
  ```

3. Create your wildcard domain.

  ```bash
  mkcert "*.localhost.pomerium.io"
  ```

4. Viola! Now you can use locally trusted certificates with pomerium!

Setting                      | Certificate file location
---------------------------- | -------------------------------------------
`certificate_file`           | `./_wildcard.localhost.pomerium.io-key.pem` |
`certificate_key_file`       | `./_wildcard.localhost.pomerium.io.pem`     |
`certificate_authority_file` | `$(mkcert -CAROOT)/rootCA.pem`              |

See also:

- [Set up a local test domain with dnsmasq](https://github.com/aviddiviner/til/blob/master/devops/set-up-a-local-test-domain-with-dnsmasq.md)
- [USE DNSMASQ INSTEAD OF /ETC/HOSTS](https://www.stevenrombauts.be/2018/01/use-dnsmasq-instead-of-etc-hosts/)
- [How to setup wildcard dev domains with dnsmasq on a mac](https://hedichaibi.com/how-to-setup-wildcard-dev-domains-with-dnsmasq-on-a-mac/)
- [mkcert](https://github.com/FiloSottile/mkcert) is a simple tool for making locally-trusted development certificates
