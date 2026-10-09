# Codex Remote TUI Bridge

Experimental bridge that lets `codex --remote ws://127.0.0.1:4747` act as a Codex remote-control controller over the ChatGPT/OpenAI relay, similar to the Codex Desktop/mobile remote-control path.

Status: private/unsupported protocol research. The complete bridge path,
including shell mode, was retested with Codex `0.160.0` on 2026-10-02 after
matching the current account-routing header behavior and per-client pairing.
This can break if OpenAI changes the remote-control protocol or enrollment policy.

## Research Use and Disclosure

This repository is proof-of-concept research published for educational and defensive purposes. The security issues demonstrated by this research were disclosed through OpenAI's formal reporting channels, followed by repeated attempts over several months to engage on remediation. It is being released so security practitioners can independently understand the risk, challenge their assumptions, and improve their defenses. Test only with accounts and systems you are authorized to use.

This is intentionally not production tooling. It uses an unsupported product protocol that can change without notice and is provided as-is.

Research write-up: [Living Off the Agent Pt1](https://ohfog.com/2026/10/09/living-off-the-agent-pt1-repurposing-chatgpt-and-codex-for-command-and-control/)

## What This Does

```text
Codex TUI
  -> local websocket bridge
  -> wss://chatgpt.com/backend-api/codex/remote/control/client
  -> ChatGPT/OpenAI relay
  -> controlled Codex host
```

The bridge is not a generic network tunnel. It forwards Codex app-server JSON-RPC inside Codex remote-control envelopes.

## Requirements

Controlled development host:

- Managed standalone Codex install.
- Logged in to an OpenAI/ChatGPT account where remote control is enabled.
- Remote-control daemon started successfully.

Controller machine:

- Codex CLI installed and logged in.
- Node.js with built-in `fetch` and modern `node:crypto` support. Node 20+ is recommended; Node 24 was used for testing.
- Browser access for the one-time OAuth step-up enrollment.
- Same account/workspace context that can see the controlled host.

No npm packages are required.

## Start The Controlled Host

On the development host you want to control:

```bash
~/.codex/packages/standalone/current/bin/codex login --device-auth
~/.codex/packages/standalone/current/bin/codex remote-control start
```

Expected success looks like:

```text
This machine is available for remote control as <name>.
Daemon used app-server:
  path: ...
  version: ...
```

If this fails with a policy/admin error, remote control is not enabled for that account/workspace.

## Install The Bridge

On the controller machine:

```bash
unzip codex-remote-tui-bridge-*.zip
cd codex-remote-tui-bridge
```

Set the Codex binary if it is not on `PATH`:

```bash
export CODEX_BIN="$HOME/.codex/packages/standalone/current/bin/codex"
export CODEX_APP_SERVER_ARGS="app-server --stdio"
```

If `node` is not on `PATH`, add it before running the scripts.

## One-Time Controller Enrollment

The bridge uses its own controller enrollment and software-held P-256 device key under:

```text
~/.codex-bridge/controller-device-key.json
~/.codex-bridge/controller-enrollment.json
```

Run enrollment:

```bash
CODEX_ALLOW_STATE_CHANGE=client-enroll-finish \
CODEX_STEP_UP_MODE=oauth \
node controller-enroll-attempt.mjs
```

The script prints an OAuth URL. Open it in a browser on the controller machine and finish the flow. On success, the script persists `~/.codex-bridge/controller-enrollment.json`.

This is an unsupported emulation of the Codex Desktop controller role. The
public Linux Codex implementation provides the remotely controlled host role;
it does not provide a Linux controller device-key store. A software-key
enrollment succeeded in the lab on 2026-06-13. During the 2026-10-02 retest,
fresh enrollment initially returned `remote_control_reauth_required` because
the bridge omitted the current first-party `ChatGPT-Account-Id` request header.
The updated scripts derive it from the bearer token as the desktop does; fresh
software-key enrollment then returned HTTP 200 at both enrollment steps.

Diagnostic compatibility overrides are available for source-comparison work:

```bash
CODEX_HTTP_ORIGINATOR="Codex Desktop"
CODEX_HTTP_USER_AGENT="Codex Desktop/<version> (<platform>; <arch>)"
CODEX_DEVICE_KEY_ID_PREFIX="dk_osn_"
```

They do not provide protected Linux key storage and were not the compatibility
fix. The required difference was the workspace/account routing header, which
the updated scripts now derive automatically.

If the browser is on another machine, forward the callback ports:

```bash
ssh -N -L 1455:127.0.0.1:1455 -L 1457:127.0.0.1:1457 <controller-host>
```

Then open the printed URL locally.

## Pair This Controller With The Host

Pairing is per enrolled controller client. An online host paired from the Mac
app is not automatically paired to this bridge identity. Generate a fresh code
on the controlled host and submit it directly to the helper without printing or
persisting it:

```bash
ssh <controlled-host> 'codex remote-control pair --json' | \
ssh <controller-host> 'CODEX_BIN=$HOME/.codex/packages/standalone/current/bin/codex \
CODEX_BRIDGE_ENROLLMENT_PATH=$HOME/.codex-bridge/controller-enrollment.json \
node /path/to/codex-remote-tui-bridge/controller-pair-attempt.mjs'
```

Without this step, initialize reaches the host but returns `Remote environment
is not paired for this client`.

Verify refresh works:

```bash
node controller-refresh.mjs
```

## Run The Bridge

If only one online remote environment is visible to the account, this may be enough:

```bash
./run-bridge.sh
```

If multiple environments are visible, select the target:

```bash
CODEX_REMOTE_ENV_NAME=<remote-host-display-name> ./run-bridge.sh
```

or:

```bash
CODEX_REMOTE_ENV_ID=<env_id> ./run-bridge.sh
```

Default local listener:

```text
ws://127.0.0.1:4747
```

Useful listener overrides:

```bash
CODEX_BRIDGE_LISTEN_HOST=127.0.0.1
CODEX_BRIDGE_LISTEN_PORT=4747
```

## Smoke Test

In another terminal on the controller machine:

```bash
node probe-bridge-local.mjs
```

Expected output includes:

```json
{
  "ok": true
}
```

## Use Codex TUI

In another terminal:

```bash
codex --remote ws://127.0.0.1:4747
```

For tmux:

```bash
tmux new-session -d -s codex-bridge \
  'CODEX_REMOTE_ENV_NAME=<remote-host-display-name> ./run-bridge.sh 2>&1 | tee -a bridge.log'

tmux new -As codex-tui \
  'codex --remote ws://127.0.0.1:4747'
```

When scripting TUI tests through tmux, type the prompt, wait briefly, then send `Enter`. Sending text plus Enter as one paste burst can cause the TUI to insert a newline instead of submitting.

## Reconnect Test

Start the bridge with the debug signal hook:

```bash
CODEX_BRIDGE_ENABLE_SIGNAL_DEBUG=1 \
CODEX_REMOTE_ENV_NAME=<remote-host-display-name> \
./run-bridge.sh
```

From another shell:

```bash
kill -USR2 "$(pgrep -f controller-bridge.mjs | head -n1)"
```

Expected bridge log sequence:

```text
debug-signal
remote-websocket-disconnected
remote-reconnect-scheduled
controller-session-refreshed
remote-controller-ready
```

An active TUI session should remain open and work after reconnect.

## Environment Variables

- `CODEX_BIN`: Codex binary path. Default: `codex`, or `~/.codex/packages/standalone/current/bin/codex` in `run-bridge.sh`.
- `CODEX_APP_SERVER_ARGS`: app-server args. Default: `app-server --stdio`.
- `CHATGPT_BASE_URL`: backend base URL. Default: `https://chatgpt.com/backend-api`.
- `CHATGPT_ACCOUNT_ID`: optional override when account-id decoding from the
  ChatGPT bearer token is unavailable.
- `CODEX_REMOTE_ENV_NAME`: select target remote environment by display/host/name.
- `CODEX_REMOTE_ENV_ID`: select target remote environment by id.
- `CODEX_BRIDGE_LISTEN_HOST`: local listen host. Default: `127.0.0.1`.
- `CODEX_BRIDGE_LISTEN_PORT`: local listen port. Default: `4747`.
- `CODEX_BRIDGE_DEVICE_KEY_PATH`: helper device key path. Default: `~/.codex-bridge/controller-device-key.json`.
- `CODEX_BRIDGE_ENROLLMENT_PATH`: helper enrollment path. Default: `~/.codex-bridge/controller-enrollment.json`.
- `CODEX_BRIDGE_ENABLE_SIGNAL_DEBUG=1`: enable `SIGUSR2` upstream-disconnect simulation.

## Current Limitations

- Unsupported/private OpenAI protocol.
- Outbound `client_message_chunk` is not implemented yet, so very large TUI-to-host JSON-RPC payloads may fail.
- Strict server `seq_id` gap detection is not implemented yet.
- Stream pong timeout handling is not implemented yet.
- Token refresh currently happens on reconnect; proactive refresh before a still-open websocket token expires still needs soak testing.
- The helper software device key is less protected than the Codex Desktop native device key.

## Safety Notes

- The scripts avoid reading `~/.codex/auth.json` directly.
- Runtime ChatGPT bearer tokens are obtained through local Codex app-server `getAuthStatus(includeToken:true, refreshToken:true)` and kept in process memory.
- Do not share `~/.codex-bridge/controller-device-key.json` or `~/.codex-bridge/controller-enrollment.json`.
- Do not expose the bridge listener beyond localhost unless you understand the consequences.
