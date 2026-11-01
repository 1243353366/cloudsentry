# Response boundaries: what CloudSentry will not do

CloudSentry collects evidence about systems its operator is authorized to inspect and
publishes a decoy that only ever answers the visitor who connected to it. Several tempting
"more aggressive" capabilities are permanently out of scope, because they act on systems
and people who did not consent. They are documented here so that a future contributor does
not have to rediscover the reasoning, and so that an operator can see the boundary up front.

## Refused: redirecting or forcing a third party's connection onto our infrastructure

A feature that stands up a VPN, tunnel, transparent proxy or DNS/routing change in order to
**make someone else's tool connect to us** is traffic interception. Concretely it would
require, at minimum:

- taking over a channel the peer chose (their configured host, their DNS answer, their
  route) rather than a channel offered to us;
- terminating or relaying a session on behalf of a party who did not select us, whose
  payload may belong to a third party such as a compromised host's owner;
- operating a network path whose failure modes and legal duties (retention, notice,
  jurisdiction, data-subject rights) we cannot satisfy from inside this package.

"Path of least resistance" is precisely the problem: the mechanism works by making an
unconsenting party's tooling prefer our endpoint. CloudSentry's decoy only ever listens on
an address its operator binds, and only ever answers the socket the visitor opened. That is
the whole of its interaction model.

## Refused: consuming a remote party's resources

Tarpitting, indefinite holds, bandwidth amplification, "make them burn CPU/credits" loops
and denial-of-wallet behaviour are all the same thing: using our listener to impose cost on
someone else. Core will not do it, and the existing limits are one-directional:

- sessions end on a fixed budget and there is no automatic restart;
- output is reserved before it is written, so an echo cannot amplify;
- the decoy closes a peer rather than holding it open, and a bare close after output
  exhaustion is intentional;
- no ghost/phantom protocol, OCR sabotage or visual-noise mode is shipped.

The one resource the decoy spends is the operator's own: bounded CPU, bounded bytes, a
bounded audit stream, and the operator's bill.

## Also out of scope

- Any outbound probe, port scan, callback, or reverse-connect of a visitor's tool. Active
  probing lives on a separate development branch, disabled by default, and is not part of
  core.
- Retaliation, flooding back, credential capture from a live third party, or interactive
  access to a visitor's system.
- Automatic escalation to law enforcement, or any claim that synthetic logs are
  admissible proof.
- Presenting synthetic evidence as real: a simulated root prompt is not a compromise, and
  a captured payload is not a verified identity.

## If you need one of these

Use a lawful, disclosed arrangement: your own isolated lab, a signed red-team engagement
with written scope, a honeypot you operate with notice appropriate to your jurisdiction, or
a provider-side sinkhole you control. Nothing in this package should be stretched into that
role.
