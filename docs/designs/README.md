# Design docs

dove's feature designs, worked out before they're built and kept in the open —
so you can see *how* a feature is reasoned about, not just the diff that lands.
Each is a proposal until it ships: it captures the design, the failure modes,
the non-goals, and the open questions. Some will be built as written, some will
change, some may never land — that's the point of writing them down first.

## Index

- [**dove-v1.md**](dove-v1.md) — the first dove: send a file out of your own
  cloud, encrypted and expiring, in one command. Two tiers (simple presigned
  vs. full end-to-end), chunked AES-256-GCM with the key living only in the URL
  fragment, an access-policy gate that counts downloads without ever seeing the
  key, a browser page that punts large files to a symmetric CLI, and dove.sh as
  the install trust anchor.
