# Killcode Server

Central API server for binary licensing and protection system.

## Architecture

**Request Flow:**
1. User uploads binary → Server stores as `{binary_id}_original` in `/uploads`
2. User creates license → Server generates overload template as `{binary_id}_overload`
3. On first download request:
   - Server checks cache for `{binary_id}_{license_id}_merged`
   - If not cached: patches license into overload → forwards to Weaver for merging
   - Weaver merges and returns download URL
   - Server downloads merged binary from Weaver → caches it in `/uploads`
4. Subsequent downloads served directly from cache (no Weaver needed)

**Storage:**
- Original binaries: `/uploads/{binary_id}_original`
- Overload templates: `/uploads/{binary_id}_overload`
- Merged binaries (cached): `/uploads/{binary_id}_{license_id}_merged`
- Metadata: MongoDB
- Real-time events: Redis pub/sub

**Architecture Detection:**
- Overload binaries mounted from `/overload/builds` → `/app/overload_bins` (read-only)
- Server auto-detects uploaded binary architecture (x86_64, ARM64, etc.)
- Selects matching overload template from versioned builds
- Supports: Linux (x86_64, x86, ARM64, ARMv7), Windows (x86_64, x86)

**Key Benefits:**
- Weaver is stateless - can restart safely
- Merged binaries persist across server restarts
- Fast downloads after first merge (cached)
- Automatic platform matching for overload selection

## Features

- Binary upload and management
- License creation with configurable policies
- On-demand binary merging with caching
- Real-time verification with grace periods
- License revocation and updates
- Analytics and telemetry dashboard
- GeoIP tracking
- User authentication (JWT)
- Real-time notifications
- SSE progress streaming

## Tech Stack

- **Framework:** Actix-Web
- **Database:** MongoDB
- **Cache/Queue:** Redis
- **Language:** Rust
- **Runtime:** Tokio
- **HTTP Client:** reqwest
- **Auth:** JWT, bcrypt
- **GeoIP:** MaxMind GeoLite2
