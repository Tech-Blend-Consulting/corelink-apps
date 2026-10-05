# CoreLink SDKs

Client libraries and container build for [CoreLink](https://usecorelink.com).

An application here never holds a credential to start with. It proves what it is
to the platform -- a Kubernetes ServiceAccount token, a signed EC2 identity
document, a host fingerprint, or a token from your own OIDC issuer -- and a grant
decides what it may do.

| Directory | What it is |
|---|---|
| `go/` | Go SDK. `go get github.com/dw-develop/tech-blend-corelink-apps/go` |
| `python/` | Python SDK |
| `node/` | Node SDK |
| `ruby/` | Ruby SDK |
| `java/` | Java SDK, dependency-free |
| `dotnet/` | .NET SDK |
| `connector/` | Dockerfile that builds a connector image from the published binary |
| `testdata/` | Fixtures every SDK is tested against, produced by the platform's own crypto |

## Installing

**Go**

```bash
go get github.com/dw-develop/tech-blend-corelink-apps/go
```

**Python, Node, Ruby** — install from this repository:

```bash
pip install "git+https://github.com/dw-develop/tech-blend-corelink-apps.git#subdirectory=python"
npm install github:dw-develop/tech-blend-corelink-apps#main --prefix-path node
bundle add corelink --git https://github.com/dw-develop/tech-blend-corelink-apps --glob ruby/*.gemspec
```

**Java and .NET** — copy the source in. Both are deliberately dependency-free:
the Java SDK is a handful of files with no build system, and the .NET SDK is two
files plus a project that exists only to run its tests.

## The connector

Most deployments run a connector beside the application. It holds sealed
envelopes it has no authority to open, so the application can fetch a secret
without a route to the platform and without anything on the path being able to
read it.

Download the binary from the registry, or build an image:

```bash
cd connector
docker build --build-arg VERSION=1.28.2 -t corelink-connector:1.28.2 .
```

The binary itself is published per platform at
`https://usecorelink.com/static/downloads/v<VERSION>/`, and the current version
is in `latest.json`.

## Which path your application takes

**With a connector** — the ordinary arrangement. The connector is granted
`secrets:cache` and holds the envelope; your application is granted
`secrets:unwrap` and opens it. Neither is granted `secrets:read`, so the only
route from a stored secret to a usable credential is the two in series and the
connector alone is worth nothing.

**Without one** — a SaaS product or a function that cannot run a sidecar
federates to its own OIDC issuer and reads directly with `secrets:read`.

Both are covered in the integration guide at
<https://usecorelink.com/docs/integrating-an-application>.

## Versioning

Tagged alongside the platform. The Go module lives in a subdirectory, so its
tags carry the directory prefix -- `go/v1.28.2` -- which is Go's convention for
a repository holding more than one module.

## Tests

Every SDK is tested against the fixtures in `testdata/`, which the platform's own
crypto produces. That is deliberate: six hand-written implementations of one wire
format drift unless something pins them, and agreeing with each other is not the
same as agreeing with the platform.

```bash
cd go      && go test ./...
cd python  && python3 -m unittest discover -s tests
cd node    && npm test
cd ruby    && ruby -Ilib test/sealed_test.rb
cd java    && javac *.java && java SealedTest
cd dotnet  && dotnet run
```
