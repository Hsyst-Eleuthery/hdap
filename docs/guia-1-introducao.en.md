# User Guide — HDAP

*Revision 2026-11-17.*

**HDAP v2.0 — protocol codename: Teleios (Téleia vási) · release codename: Teleios**

**Written by Thaís (op3n/op3ny)**

---

## What is HDAP?

Imagine your files today live in a rented property. You pay to use it, but the property is not yours: the owner decides who enters, what can be stored, and when the door is locked. If the contract ends, everything inside becomes a negotiation. You may have a copy of a document, but not the document itself; you may pay on time, but have no guarantee the service will continue tomorrow; you may trust the provider, but have no way to prove you trusted the right thing.

**HDAP (Hsyst Descentralized Archive Protocol)** is an attempt to solve this problem from the bottom up. Instead of a company owning your files, there is a protocol. Instead of an account that can be suspended, there is an identity that stays with you. Instead of a backup promise, there are copies anyone can verify. And instead of an invisible authorization hidden in a database, there are signed permissions that you publish yourself and that anyone can read.

The central idea is small enough to be understood and strong enough to be verified. Each file in HDAP is defined by three independent facts. The first is a **hash**: a fingerprint of the content, so a file's address comes from what it is, not the name someone gave it. The second is a **signature**: a mathematical proof of who published it, which anyone can verify without asking a server for permission. The third is a **history**: the node storing the file records where it was born, which copies exist, and who authorized each copy. If you understand these three facts, you understand the backbone of everything else.

The rest of the protocol exists to protect these three facts. Identity protects the signature. Permissions protect access. Bandwidth protects the resource of whoever stores. Replication protects the file against a server going down. Possession transfer and home succession protect you against the operator disappearing. None of this is decoration: each piece answers a concrete question about what happens when something goes wrong.

It is important to say, from the start, what HDAP **is not**. It is not a blockchain, it has no native currency in its core, and it does not promise network anonymity. It is not a social network nor a substitute for the entire internet. It is an archival layer with explicit rules, designed for those who want to own their identity and keep their files accessible even when the original node goes offline. This honesty is not a weakness; it is what makes the existing guarantees truly reliable.

---

## Why it exists

On today's internet, you do not store your files: you rent access to them. The platform decides the format, the limit, the removal policy, and the price. When the account is closed, the file may still exist on someone's disk, but you lost access, lost proof of authorship, and lost the ability to migrate. The relationship is always asymmetric: the platform knows everything about you, and you know almost nothing about what it will do tomorrow.

HDAP inverts this relationship. Identity is a key pair that stays on your computer, not in a registry. The file is identified by content, not by a company's name. Permission is a document signed by you, not a setting someone can change without notice. The replica is verifiable by hash, not a backup promise. And the home — your space within a server — can move without your identity changing name. If the node goes down, the file may be elsewhere. If the operator changes the rules, you can take your home to another pyle.

This inversion has a cost, and the cost is responsibility. There is no "forgot my password", no support desk to reset your access, and no central authority to fix a lost vault. What exists, in return, is a set of mechanisms you can understand, audit, and repeat. HDAP exchanges blind trust for verifiable work, and assumes the user prefers to be an owner rather than a customer.

---

## The five things HDAP does

To avoid getting lost in the details, five ideas are worth fixing. They appear throughout the rest of the guide and explain practically everything the system does.

First, **your identity is yours, literally**. There is no email, CPF, or central account. Your identity is a key pair that stays on your computer. The private key is never sent to anyone; the server knows only the public key, and it is with that key that it verifies it was you who acted. The good consequence is that no server can ban you from the entire network, because there is no authority that commands everyone. The difficult consequence is that there is no password recovery: if you lose the vault and the passphrase, the identity is gone. This is the part of the guide you should read with the most attention, and it has a chapter entirely dedicated to it.

Second, **every file has proof of authorship**. When you publish something, it is not a hidden line in a database that only the company sees. It is a signed document that anyone can read and verify: who published, when, and the exact fingerprint of the bytes. If someone alters the content, the hash changes and the fraud becomes visible. In HDAP almost everything is a document: your identity, permissions, an alias, a transfer offer, a succession power of attorney. Learning to read a `.hdap` document is learning to read the protocol.

Third, **publishing costs work, not money**. Upload is not free in terms of resource: it consumes disk and bandwidth. Instead of charging a hidden fee, HDAP asks for a light proof of work. Your client solves a small mathematical challenge and receives a bandwidth credential, which is then consumed at publish time. It is like stamping a letter before mailing: the cost is small for those who publish for real and prohibitive for those who try to flood the network. The economic module exists, but is optional; basic archiving does not depend on any currency.

Fourth, **the network has no single owner**. There is no "HDAP server". There are several pyles, which communicate with each other, verify each other's signatures, and replicate content when it makes sense. If a pyle turns malicious, you take your home to another, signing the move without asking the old one for permission. If the pyle disappears while you are offline, a previously signed power of attorney may allow a trusted substitute to take over the home. The system was designed to survive the loss of any individual node.

Fifth, **you choose how to use it**. The same protocol has three entry points. The desktop application, `hdap-gui`, hides complexity and offers an experience similar to a file manager. The command line, `hdap-cli`, serves for automation and server operation. And the node itself, `hdap-server`, is the piece that stores content and participates in federation. All three speak the same protocol and share the same core, so a document rule is never reimplemented one way on the server and another on the client.

---

## Where trust is replaced by proof

It is worth pausing on the phrase that summarizes the project's philosophy: **trust should not be required where it can be replaced by proof**. Every time HDAP needs to decide something, it tries to answer three questions. Who signed this? Are the bytes the same as those signed? Does this person have the right to do this now? If any of these answers depends solely on an operator's word, the design is not ready.

In practice, this means that every question you would ask a common cloud gains a verifiable answer in HDAP. Who published this file? A signature over the raw bytes. Did the file change? The content hash is part of the address. Can I read? A signed permission from the owner says yes, or the node refuses. Is this copy authentic? The node verifies the hash upon receipt and records the origin. And if the server disappears? The home can migrate, or be assumed by a previously authorized fallback. And if the operator lies? You change pyle and take your identity; the signed history remains verifiable.

This is the difference between a system you trust because you have no choice and a system you trust because you verified. HDAP does not ask for faith; it asks you to repeat the sequence of proofs, if you wish. And because the proofs are mathematical, any client — including one you wrote yourself — arrives at the same conclusion.
