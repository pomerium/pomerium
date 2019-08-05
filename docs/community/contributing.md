---
title: Contributing
description: >-
  This document describes how you can find issues to work on, setup Pomerium
  locally for development, and get help when you are stuck.
---

# Contributing

You can have a direct impact on the project by helping with its code or documentation. To contribute to Pomerium, open a [pull request](https://github.com/pomerium/pomerium/pulls) (PR). If you're new to our community, that's okay: **we gladly welcome pull requests from anyone, regardless of your native language or coding experience.**

## Code

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

## Documentation

Pomerium's documentation is available at <https://www.pomerium.io/docs>. If you would like to make a fix to the docs, please submit an issue here describing the change to make.
