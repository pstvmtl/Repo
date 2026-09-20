# DeFi Pulse Monitor

Checks portfolio value, PnL, and pool health across a Robinhood-chain EVM wallet and a
Solana wallet (including a direct-RPC decode of Raydium CLMM positions), flags risk
conditions, and emails a summary. Runs on a schedule via
`.github/workflows/defi-pulse.yml` (9:00 AM / 1:00 PM / 6:00 PM EDT), and can be run
manually via the "Run workflow" button in the Actions tab.

## Required repository secrets

Set these under **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Value |
|---|---|
| `ZERION_API_KEY` | Zerion API key (used for position values / PnL) |
| `ALCHEMY_API_KEY` | Alchemy Solana RPC API key (used to decode Raydium CLMM positions) |
| `COINGECKO_API_KEY` | CoinGecko demo API key (used for major-asset prices and extreme-move cross-checks) |
| `GMAIL_SMTP_USER` | The Gmail address the alert is sent **from** |
| `GMAIL_SMTP_APP_PASSWORD` | A [Gmail app password](https://myaccount.google.com/apppasswords) for that address (not the account password — requires 2-Step Verification to be enabled) |
| `ALERT_EMAIL_TO` | The address the alert is sent **to** |

The wallets checked are hardcoded in `scripts/defi_pulse.py` (`EVM_WALLET`, `SOL_WALLET`) —
these are public addresses, not secrets, but can be overridden via env vars of the same
name if you ever need to point this at different wallets.

## How it works

- **Zerion** — total value + 1-day PnL for the EVM wallet (complex + simple positions),
  and simple wallet balances for the Solana wallet. Zerion does not support
  `only_complex` for Solana, so Raydium LP positions are *not* visible to Zerion.
- **Raydium (Solana)** — the script finds Raydium position NFTs owned by the wallet via
  `getTokenAccountsByOwner`, derives the `PersonalPositionState` PDA
  (`["position", nft_mint]` under the Raydium CLMM program), fetches and decodes that
  account directly (no `getProgramAccounts`, which is rate-limited on free RPC tiers),
  then decodes the referenced `PoolState` account for the current tick/price.
- **GeckoTerminal** — pool TVL, 24h volume, and 24h price change for every pool behind a
  held position. EVM (Uniswap v3/v4) pools are resolved from Zerion's token addresses via
  GeckoTerminal's token→pools search, matched on fee tier when available.
- **CoinGecko** — used as the second source for the "extreme move on a token <48h old"
  safety check.

## Safety rules implemented

- Never reports a >20% move on a <48h-old pool without a second-source cross-check
  (falls back to an explicit "UNVERIFIED" note if no second source is available).
- Flags 2+ pools for the same token showing suspiciously identical 24h % moves.
- Flags tokens whose name/symbol matches a synthetic/leveraged pattern (`x1L`/`x2L`/`x3L`)
  or that Zerion's registry marks unverified.
- Every number in the summary is tagged with its data source.
- Each run is compared against `data/last_snapshot.json` (committed back to the repo by
  the workflow) to report whether a move is continuing or reversing.

## DST note

The cron schedule is pinned to EDT (UTC-4). When US clocks fall back to EST in November,
the workflow will fire an hour later local time until the cron offsets in
`.github/workflows/defi-pulse.yml` are bumped by an hour.
