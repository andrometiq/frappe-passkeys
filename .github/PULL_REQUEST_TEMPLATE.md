<!-- Thanks for contributing! See CONTRIBUTING.md for the full guide. -->

**Which branch should this merge into?**
<!-- develop for features; version-15 / version-16 for fixes to a released line -->

**What does this change, and why?**
<!-- Describe the change and the problem it solves. Link the issue: Closes #123 -->

### Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): subject`)
- [ ] Targets the correct branch (`develop` for features, `version-*` for a released-line fix)
- [ ] Tests pass locally (server, JS unit, Cypress) and `pre-commit` is clean
- [ ] New behaviour is covered by tests; business logic and validation stay server-side
- [ ] Documentation under `docs/` updated where behaviour changed
