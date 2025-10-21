# BarTAB Chat

We use Discord. Or rather, we used to enjoy using Discord.

Since Discord got bought out, it's been going downhill fast. Here in Australia, they're starting to roll-out requiring photos for prove age verification. The other week Discord had a data breach where this ID data was stolen. That's the final straw.

As grass touching developers who are sick of this shit and want to go back to the time of monkey, we thought it would be funny (and useful) to build our own simpler version. The alternatives to Discord aren't great, and Discord basically has a monopoly on this space. So here we are... building a lightweight, self-hostable chat system that we actually control. Until we forget and drop the project :tm:.

## What We Are Attempting To Building

A lightweight group chat system that's self-hostable, modular, and developer-friendly. Each server runs as its own independent instance, managing its own users, rooms, and media. No corporate overlords, no ID requirements, no data breaches of your personal documents until we realised we cooked the media storage and ended leaking data?

The core design is pretty simple:

- **Write-Ahead Logging (WAL)**: Everything is an event in order. No weird state bugs as everything should be replicated. Though this might cause some chaos when it gets large, I'm sure we will think of a solution before that is a problem :tm:.
- **Composable microservices**: "Clean" APIs between services. Each does one thing, for example an auth service, media service and chat service.

We're starting with **plaintext messaging for the MVP** because let's be real, we need something that actually works first. Once that's "solid", or if we have someone who has a high ABV score and motivation for developing this, we'll add proper end-to-end encryption using Olm (Signal like) or Megolm (Matrix like).

- **Simple auth that actually makes sense**: JWT tokens for everything. Maybe OIDC later if we need it or think it could be funny.
- **Long polling instead of WebSocket hell**: The `/sync` endpoint just works. No sticky sessions, no reconnection chaos, no fucking about with websockets or SSE. Though we may either switch to SSE if we find it works better.
- **Bots are first-class citizens**: They use the same APIs as regular clients so we should have a strong SDK for this. Let's build snail race on another platform.
- **Media handling that doesn't suck**: Dedicated media service handles uploads, thumbnails, and caching lets say mini CDN-like.

Everything runs in Docker containers with SQLite. The end. We'll add backup scripts so you don't lose your data maybe. Ideally, we also build some developer tools which can help manage the environment as well.

Bots can run as containers in the same Docker stack which could be nice having it all connected via internal virtual networks. But we do need to have a way for them to connect remotely as well.

## Core Services

We split this thing into three services that work together:

- **Authentication Service**: Handles logins, creates JWT tokens, and tells other services who's allowed to do what. Without this running, nothing else works.
- **Chat Service**: Rooms, messages, who's online. Everything goes into an append-only log so message order never gets screwed up :tm:. Uses long polling to deliver updates.
- **Media Service**: Handles file uploads and downloads. Basically a mini CDN with thumbnail generation. Can serve files publicly or require auth.
