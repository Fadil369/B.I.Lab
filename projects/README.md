# B.I.Lab projects

Public BrainSAIT projects, indexed alongside this repo's [reusable workflows](../README.md#workflows).
Each project is a git submodule pinned to a commit, so this repo holds links, not copies.

| Project | What it is | Stack |
| --- | --- | --- |
| [`agent-visibility`](https://github.com/Fadil369/agent-visibility) | _No description on GitHub yet_ | TypeScript, Cloudflare Workers |
| [`brainsait-superagent`](https://github.com/Fadil369/brainsait-superagent) | Multi-brain super agent with Lark integration, self-upgrading model routing, and Run:ai GPU orchestration | TypeScript |
| [`fadil369.github.io`](https://github.com/Fadil369/fadil369.github.io) | BrainSAIT OID Marketplace: digital identity and badging storefront (AR/EN, SAR) | HTML, GitHub Pages |
| [`brainsait-ai-automation`](https://github.com/Fadil369/brainsait-ai-automation) | _No description on GitHub yet_ | Python |

## Working with the submodules

```sh
git clone --recurse-submodules https://github.com/Fadil369/B.I.Lab.git
# or, in an existing clone:
git submodule update --init --recursive
# move a project to its latest commit, then commit the new pointer:
git submodule update --remote projects/<name>
```

## Adding a project

Only repositories that are **public** and owned by `Fadil369` belong here. Private, client, or
regulated-data projects, and third-party clones, are not listed. **Never put PHI, secrets, or client
names in this repo** (see the [compliance guardrails](../README.md#compliance-guardrails-hipaa--nphies)).

```sh
git submodule add https://github.com/Fadil369/<name>.git projects/<name>
```

Then add a row to the table above.
