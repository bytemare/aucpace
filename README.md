# AuCPace

AuCPace implements the (strong) AuCPace protocol that allows for mutual client-server authentication without the server knowing the client's secret.

This implements https://tools.ietf.org/html/draft-haase-aucpace-01

!!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT. THERE ARE ABSOLUTELY NO WARRANTIES. !!!


AuCPace defines a new generation of password based authentication, alongside OPAQUE (link).
It is specially suitable for constrained environments like the IIoT but can perfectly be used for webservice authentication. 

Advantages:
> todo

## Get it

go get etc.

## Use it

API description.

## Understand it

AuCPace is an asymmetric PAKE and, in fact, a strong augmentation of CPace.
It leverages the magic of an OPRF to protect a blind salt and derive a shared secret with it.

A high level explanation of PAKEs can be found here (link to pake pkg).

All cryptographic operations use the PAKE package as an interface to reference implementations and the standard library.

## Security Considerations

- As of this version, this is an implementation following an internet draft, and is not suited to protect sensitive information or production environments.
- It is very important to somehow ensure client integrity. This protocol won't protect you if the client is corrupted or being tampered with.
- Add security recommendations from the draft. 

## Deploy it

Don't, yet.

## Work on it

wip :
- thorough testing
- better verifier setup
- better support of legacy-style databases