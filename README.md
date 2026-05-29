# Stage336: Safe Live Intelligence Fetcher

Stage336 adds a safe live intelligence layer to the QSP/VEP evidence system.

It periodically fetches public security and AI-risk metadata from sources such as:

- GitHub Advisory metadata
- CVE/NVD metadata
- OWASP update metadata
- arXiv research metadata

## Safety Boundary

Stage336 does **not** collect:

- exploit code
- attack prompts
- payloads
- bypass instructions
- malware samples
- automated attack logic

It collects only safe audit metadata:

- category
- title
- summary
- published date
- impact scope
- tags
- source URL

## Public Output

The private fetcher generates public, safe metadata files:

- `docs/intel/index.html`
- `docs/intel/index.json`

## Private Core

The fetcher implementation is kept private and excluded from GitHub:

- `private_core/`
- `data/`

## Value

Stage336 moves the system from a static evidence catalog to a live AI/security intelligence monitoring layer.

This strengthens the product direction as:

**AI safety audit infrastructure**

not an attack or exploit platform.

## License

MIT License

Copyright (c) 2025 Motohiro Suzuki
