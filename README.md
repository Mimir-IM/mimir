# Mimir

A Rust networking library for secure peer-to-peer messaging and group chat, built on top of the [Yggdrasil](https://yggdrasil-network.github.io/) overlay network. Designed for mobile and desktop use, with cross-platform FFI bindings via [UniFFI](https://mozilla.github.io/uniffi-rs/).

## Features

- **P2P Direct Messaging** — Authenticated, encrypted connections between peers using Ed25519 identity keys
- **Voice Calls** — Real-time call signaling and raw audio packet transport
- **File Transfers** — Inline messages for small payloads; persistent data streams for large files (>64 KiB) with progress callbacks
- **Contact Requests** — Friend request flow with introductory message
- **Group Chat (Mediator)** — Server-assisted group chat with end-to-end encrypted messages (ChaCha20-Poly1305)
- **Peer Discovery** — UDP tracker protocol for resolving Ed25519 public keys to Yggdrasil routing keys
- **Cross-Platform** — Android (JNI via UniFFI), iOS (Swift via UniFFI), and desktop targets

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Your Application                  │
│         (Kotlin / Swift / Rust / Python)            │
└───────────────┬─────────────────┬───────────────────┘
                │ UniFFI FFI      │ UniFFI FFI
       ┌────────▼───────┐  ┌──────▼──────────┐
       │   PeerNode     │  │  MediatorNode   │
       │  (P2P + calls) │  │  (group chat)   │
       └────────┬───────┘  └──────┬──────────┘
                │                 │ shares Yggdrasil node
                └────────┬────────┘
                ┌────────▼────────┐
                │  Yggdrasil      │
                │  Overlay Network│
                └─────────────────┘
```

The library exposes two main objects:

- **`PeerNode`** — manages direct peer-to-peer connections, message delivery, calls, and file transfers
- **`MediatorNode`** — connects to group chat servers (mediators), manages group membership, and delivers encrypted group messages

Both share the same underlying Yggdrasil node and signing key, so only one network identity is needed.

## Quick Start

```rust
// Build the PeerNode
let listener: Arc<dyn PeerEventListener> = Arc::new(MyEventListener);
let provider: Arc<dyn InfoProvider> = Arc::new(MyInfoProvider);

let node = PeerNode::new(
    signing_key_seed,          // 32-byte Ed25519 seed
    ygg_peers,                 // Vec<String> of Yggdrasil bootstrap URIs
    port,                      // u16 listening port
    trackers,                  // Vec<String> of tracker addresses
    listener,
    provider,
)?;

// Connect to a peer by their public key
node.connect_to_peer(their_pubkey);

// Send a text message
node.send_message(their_pubkey, guid, reply_to, send_time, edit_time, msg_type, data);

// Attach a MediatorNode for group chat (shares the Yggdrasil node)
let med_listener: Arc<dyn MediatorEventListener> = Arc::new(MyMedListener);
let mediator = MediatorNode::new(Arc::clone(&node), mediator_port, med_listener)?;
mediator.connect_to_mediator(mediator_pubkey, mediator_address);
```

## API Reference

### `PeerNode`

| Method | Description |
|--------|-------------|
| `new(seed, peers, port, trackers, listener, provider)` | Create and start the node |
| `public_key()` | Get the 32-byte Ed25519 public key |
| `connect_to_peer(pubkey)` | Initiate connection to a peer |
| `disconnect_peer(pubkey)` | Close a peer connection |
| `send_message(pubkey, guid, reply_to, send_time, edit_time, msg_type, data)` | Send a message |
| `send_contact_request(pubkey, message)` | Send a friend request |
| `send_contact_response(pubkey, accepted)` | Accept or reject a friend request |
| `start_call(pubkey)` | Initiate a voice call |
| `answer_call(pubkey, accept)` | Accept or reject an incoming call |
| `hangup_call(pubkey)` | End the active call |
| `send_call_packet(pubkey, data)` | Send a raw audio packet |
| `announce_to_trackers()` | Announce ephemeral address to trackers |
| `set_ygg_peers(peers)` | Update Yggdrasil bootstrap peers |
| `set_network_online(online)` | Notify about device connectivity changes |
| `add_peer(uri)` / `remove_peer(uri)` | Dynamic Yggdrasil peer management |
| `wait_for_peer_info(timeout_ms)` | Long-poll for Yggdrasil peer metric changes |
| `get_peers_json()` / `get_paths_json()` / `get_tree_json()` | Network diagnostics |
| `retry_peers_now()` | Trigger immediate peer reconnection |
| `stop()` | Shut down the node |

### `MediatorNode`

| Method | Description |
|--------|-------------|
| `new(peer_node, port, listener)` | Create the mediator client (shares PeerNode's Yggdrasil) |
| `connect_to_mediator(pubkey, address)` | Connect to a mediator server |
| `create_chat(mediator_pubkey, name, description, avatar)` | Create a new group (includes PoW) |
| `delete_chat(mediator_pubkey, chat_id)` | Delete a group |
| `update_chat_info(mediator_pubkey, chat_id, name, description, avatar)` | Update group info |
| `subscribe(mediator_pubkey, chat_id)` | Subscribe to group message push |
| `send_group_message(mediator_pubkey, chat_id, guid, timestamp, encrypted_data)` | Send an encrypted message |
| `delete_message(mediator_pubkey, chat_id, guid)` | Delete a message by client GUID |
| `get_last_message_id(mediator_pubkey, chat_id)` | Get the latest server message ID |
| `get_messages_since(mediator_pubkey, chat_id, since_id, limit)` | Fetch message history |
| `add_user(mediator_pubkey, chat_id, user_pubkey)` | Add a member |
| `delete_user(mediator_pubkey, chat_id, user_pubkey)` | Remove a member |
| `change_member_status(mediator_pubkey, chat_id, user_pubkey, permissions)` | Change member role |
| `leave_chat(mediator_pubkey, chat_id)` | Leave a group |
| `send_invite(mediator_pubkey, chat_id, to_pubkey, encrypted_key_data)` | Invite someone |
| `respond_to_invite(mediator_pubkey, invite_id, accepted)` | Accept or decline an invite |
| `update_member_info(mediator_pubkey, chat_id, encrypted_info, timestamp)` | Update your profile |
| `get_members_info(mediator_pubkey, chat_id, last_update)` | Get all member profiles |
| `get_members(mediator_pubkey, chat_id)` | Get member list with online status |
| `stop()` | Shut down the mediator client |

## Callbacks

Implement these traits (callback interfaces) in your application:

### `PeerEventListener`

```
on_connectivity_changed(is_online)
on_peer_connected(pubkey, address)
on_peer_disconnected(pubkey, address, dead_peer)
on_message_received(pubkey, guid, reply_to, send_time, edit_time, msg_type, data)
on_message_delivered(pubkey, guid)
on_incoming_call(pubkey)
on_call_status_changed(status, pubkey)
on_call_packet(pubkey, data)
on_file_receive_progress(pubkey, guid, bytes_received, total_bytes)
on_file_send_progress(pubkey, guid, bytes_sent, total_bytes)
on_contact_request(pubkey, message, nickname, info, avatar)
on_contact_response(pubkey, accepted)
on_tracker_announce(ok, ttl)
```

### `MediatorEventListener`

```
on_connected(mediator_pubkey)
on_subscribed(mediator_pubkey, chat_id, last_message_id)
on_push_message(chat_id, message_id, guid, timestamp, author, encrypted_data)
on_system_message(chat_id, message_id, guid, timestamp, body)
on_push_invite(invite_id, chat_id, from_pubkey, timestamp, chat_name, ...)
on_member_info_request(chat_id, last_update) -> MemberInfoData?
on_member_info_update(chat_id, member_pubkey, encrypted_info, timestamp)
on_member_online_status_changed(chat_id, member_pubkey, is_online, timestamp)
on_disconnected(mediator_pubkey)
```

### `InfoProvider`

```
get_my_info(since_time) -> ContactInfo?
get_contact_update_time(pubkey) -> i64
update_contact_info(pubkey, info)
get_files_dir() -> String
get_peer_flags(pubkey) -> i32   // 0=stranger, 1=contact
```

## Group Chat Crypto

Namespace-level utility functions for encrypting/decrypting group messages:

```rust
// Generate a new random shared key for a group
let key = generate_shared_key();  // -> Vec<u8> (32 bytes)

// Encrypt/decrypt group messages with ChaCha20-Poly1305
let ciphertext = encrypt_message(plaintext, shared_key);
let plaintext  = decrypt_message(ciphertext, shared_key)?;

// Wrap the shared key for a specific recipient using ECIES
let wrapped = encrypt_shared_key(shared_key, recipient_ed25519_pubkey);
let key     = decrypt_shared_key(wrapped, my_signing_seed)?;
```

**Message format:** `[nonce(12)] [ciphertext] [tag(16)]`
**ECIES wrap format:** `[eph_pubkey(32)] [nonce(12)] [ciphertext] [tag(16)]`
**Key derivation:** Ed25519 → X25519 (curve25519-dalek), X25519 ECDH, HKDF-SHA256

## Building for Android

### Prerequisites

```bash
# Add Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Install Android NDK via Android Studio: SDK Manager → SDK Tools → NDK (Side by side)
```

### Build

```powershell
.\scripts\build_android.ps1
# Options:
#   -NdkVersion "26.2.11394342"   (default)
#   -ApiLevel   "23"              (default)
#   -Debug                        (release build by default)
```

### Outputs

```
jniLibs/
  arm64-v8a/libmimir.so
  armeabi-v7a/libmimir.so
  x86/libmimir.so
  x86_64/libmimir.so

kotlin-bindings/uniffi/mimir/mimir.kt   ← auto-generated Kotlin bindings
```

### Android Project Integration

1. Copy `jniLibs/` into your Android module (next to `src/`)
2. Copy `kotlin-bindings/uniffi/mimir/mimir.kt` into your source tree
3. Add to `build.gradle`:

```groovy
dependencies {
    implementation "net.java.dev.jna:jna:5.18.1@aar"
}
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `ygg_stream` | Async connections over Yggdrasil |
| `yggdrasil` | Yggdrasil overlay node |
| `ed25519-dalek` | Ed25519 signing and verification |
| `chacha20poly1305` | AEAD encryption (RFC 8439) |
| `x25519-dalek` / `curve25519-dalek` | X25519 ECDH + Ed25519→X25519 conversion |
| `hkdf` / `sha2` | Key derivation (HKDF-SHA256) |
| `rand` | Cryptographic RNG |
| `serde_json` | JSON serialization |
| `uniffi` | Cross-language FFI bindings |
| `thiserror` | Error type derivation |
| `android_logger` | Logcat logging (Android only) |

## License

[Mozilla Public License 2.0](LICENSE)