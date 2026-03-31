# Agent Workflows

This guide explains how AI agents can use TIDBIT-share-WEAVE to review, version, sign, and collaborate with other agents or swarms without disappearing into an untraceable automation layer.

## Why Agents Need A Different Guide

Human users can read the normal UI and make decisions directly.

Agents are different:

- they act through APIs and policies
- they may run in parallel
- they may review without signing
- they may propose edits without final approval
- they need attributable identities in the custody ledger

The goal is not to let agents operate invisibly.

The goal is to make agent actions:

- attributable
- reviewable
- exportable
- policy-bound

## Core Model

In TIDBIT-share-WEAVE, an agent should be treated as a first-class actor, not as a hidden helper under a human session.

That means an agent should have:

- an agent identity
- an agent token
- a policy scope
- a document access scope
- a visible event trail

Examples of agent actions that should be logged:

- review a document
- summarize a document
- propose edits
- create a new document version
- sign a document if policy permits
- decline or flag a document

## Single-Agent Workflow

The simplest agent path looks like this:

1. A human uploads a document.
2. A human or policy engine registers an agent identity.
3. The agent receives access to a document.
4. The agent fetches document metadata and the review payload.
5. The agent inspects the file.
6. The agent either:
   - records a review action
   - proposes a version
   - signs if permitted
7. The resulting actions appear in the same custody ledger as human actions.

This is useful when one agent is responsible for:

- compliance review
- contract analysis
- classification
- policy enforcement
- signature recommendation

## Multi-Agent Or Swarm Workflow

The more interesting path is a swarm or multi-agent workflow.

In that model, multiple agents collaborate on the same document while staying individually attributable.

Example:

1. `Agent A` reads the document and extracts obligations.
2. `Agent B` checks policy or risk language.
3. `Agent C` proposes edits or a new version.
4. `Agent D` prepares a signing recommendation.
5. A human or policy gate decides whether signing is allowed.
6. The final approval is recorded with the responsible actor.

The point is not just automation speed.

The point is that the system can later answer:

- which agent reviewed the document
- which agent proposed the edit
- which agent recommended approval
- whether any agent signed
- which human accepted or rejected the agent path

## Recommended Swarm Rules

If you are running multiple agents, use these rules:

- one agent identity per role
- never let multiple agents share one token
- require version creation instead of silent overwrite
- require human or explicit policy approval before final sign when risk is high
- keep separate event labels for review, edit, sign, and decline
- export evidence after important flows

This keeps the custody record understandable even when several automations are involved.

## Agent Onboarding

The current backend includes agent registration and document policy endpoints.

Operationally, onboarding should look like this:

1. Create the agent identity.
2. Issue the agent token.
3. Assign the agent purpose.
4. Set the document policy.
5. Limit whether the agent may:
   - review
   - create versions
   - sign
   - only recommend actions
6. Record the agent's output in the document ledger.

Recommended metadata for each agent:

- agent id
- display name
- model or system name
- organization or operator
- policy scope
- environment or run id
- whether the agent is advisory or authoritative

## Review With Other Agents

Agents can also review documents with other agents before any signing happens.

Example pattern:

- `Research agent` extracts context
- `Redline agent` suggests edits
- `Policy agent` checks for restricted terms
- `Approval agent` decides whether the file may move forward

Each stage should produce a logged event or a new version rather than a hidden change.

That way users can see:

- who reviewed first
- what changed
- why it changed
- whether the later signer approved the same version

## Signing With Agents

Agent signing should be more constrained than human signing.

Recommended policy:

- allow agents to sign only on low-risk or machine-generated documents
- require human co-sign or explicit policy approval for high-risk documents
- distinguish agent signatures from human wallet signatures in the UI and exports

The important question is not just "can the agent sign?"

The important question is "under what policy was the agent allowed to sign?"

## Evidence Export For Agent Activity

When users export evidence, agent activity should be visible in the package.

That evidence should preserve:

- the document id
- the version lineage
- the actor identity
- the actor type
- the timestamp
- the policy result
- the signature type if any
- the before/after relationship if the agent created a version

This is what makes the app useful for audit and review later.

## Human + Agent Collaboration Model

The best product model is not "agents replace people."

It is:

- humans own authority
- agents accelerate review and drafting
- policies define what agents may do
- the ledger proves who did what

This makes the tool useful for:

- solo founders using AI for contract review
- crypto teams routing governance or vendor documents
- security teams collecting attributable review evidence
- multi-agent systems that need proof of process

## What Users Should Be Told

If you are documenting agent usage for customers, keep the message simple:

- agents can review
- agents can propose edits
- agents can create versions
- agents can sign only if allowed
- every agent action is recorded
- evidence exports can show both human and agent activity

## Current Boundary

The current product has the right direction for agent participation, but it still needs deeper production polish in these areas:

- richer policy controls
- broader agent-specific UI
- stronger deployment examples
- more explicit multi-agent templates
- fully finished browser-side PQ paths for all signing modes

Even with that boundary, the important part is already true:

TIDBIT-share-WEAVE is not treating agent actions as hidden automation. It is treating them as accountable workflow events.
