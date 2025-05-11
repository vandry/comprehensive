<!-- cargo-rdme start -->

[`comprehensive`] integration for [`warm_channels`]

This crate defines a single Comprehensive [`Resource`]
[`WarmChannelsDiag`] which makes diagnostic information about all
[`warm_channels`] client channels available over HTTP.

This is a separate crate for dependency reasons (to avoid a crate in the
`comprehensive` repo depending on `warm_channels` which depends back on
another crate in the `comprehensive` repo).

<!-- cargo-rdme end -->
