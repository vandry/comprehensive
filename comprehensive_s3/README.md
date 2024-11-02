<!-- cargo-rdme start -->

[`comprehensive`] [`Resource`] generator for using S3 buckets

This crate provides a macro for declaring an S3 bucket as a
[`comprehensive::Resource`]. It is a thin wrapper over the
[`s3::Bucket`] type. When included in a [`comprehensive::Assembly`]
it probes the bucket periodically as a health check signal.

```rust
// Defines a new type "SomeBucket" which is a Resource with
// display name "My storage". It installs command line flags
// beginning with "--app-data-" for specifying the bucket.
comprehensive_s3::bucket!(SomeBucket, "My storage", "app-data-");

// It can later be used as a dependency for another Resource:
#[derive(comprehensive::ResourceDependencies)]
struct OtherDependencies {
    bucket: std::sync::Arc<SomeBucket>,
}
```

# Command line flags for buckets

| Flag                     | Default  | Meaning                 |
|--------------------------|----------|-------------------------|
| `--PREFIXs3-endpoint`    | Auto     | Endpoint (usually https://...) If unset, [`s3::Region`] builtins will be used. |
| `--PREFIXs3-region-name` | Required | Region name as a string. |
| `--PREFIXbucket-name`    | Required | Bucket name as a string. |

<!-- cargo-rdme end -->
