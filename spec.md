# Specification

## Summary
**Goal:** Add a Video Analysis dashboard tab where users can upload and preview a local video, optionally apply in-browser sharpening, and search existing incident logs via a chatbox that returns a time-sorted timeline.

**Planned changes:**
- Add a new “Video Analysis” tab in the Dashboard with local video file upload (.mp4, .webm) and an in-app preview player plus basic metadata (filename, duration when available) and a clear empty state.
- Implement client-side video sharpening for the previewed video with an on/off toggle, adjustable intensity, and safe fallback to original playback with a non-crashing error message if unsupported.
- Add a chat-style panel in the Video Analysis tab that accepts a text query and displays results as a readable, time-sorted timeline (or an English “no matches” response) and supports clearing results without page reload.
- Add a backend query method in `backend/main.mo` to search detection logs, alert records, and suspicion logs for matching text (optionally filtered by videoId), returning a unified timeline sorted consistently by timestamp with required fields for rendering, and protected by existing read permissions.
- Wire the chatbox to the backend timeline search via a new React Query hook in `frontend/src/hooks/useQueries.ts`, including loading and error states and rendering the returned timeline in the assistant response.

**User-visible outcome:** Users can open a new Video Analysis tab, upload and preview a local video, toggle and adjust sharpening in the browser, and use a chatbox to search existing logs and receive a time-ordered incident/object timeline (or a clear no-results message).
