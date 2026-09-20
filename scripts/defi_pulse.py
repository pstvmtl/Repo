#!/usr/bin/env python3
"""DeFi Pulse: check wallet positions across Zerion, GeckoTerminal, Raydium (direct RPC)
and CoinGecko, flag risk conditions, compare against the previous run, and email a summary.
"""
import base64
import hashlib
import json
import os
import re
import smtplib
import struct
import sys
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText

import requests

EVM_WALLET = os.environ.get("EVM_WALLET", "0x889e1cd896f611a3cba990fce8dbd54802f904e2")
SOL_WALLET = os.environ.get("SOL_WALLET", "EghVz6qV3bGEAX85SQc38htEZiorou9TJxCcWpfHsa9U")

ZERION_API_KEY = os.environ["ZERION_API_KEY"]
COINGECKO_API_KEY = os.environ["COINGECKO_API_KEY"]
ALCHEMY_SOLANA_RPC = os.environ.get(
    "ALCHEMY_SOLANA_RPC",
    "https://solana-mainnet.g.alchemy.com/v2/" + os.environ.get("ALCHEMY_API_KEY", ""),
)

RAYDIUM_CLMM_PROGRAM = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

SNAPSHOT_PATH = os.environ.get("SNAPSHOT_PATH", "data/last_snapshot.json")

VOLUME_FLAG_THRESHOLD_USD = 0.0
POOL_SHARE_FLAG_PCT = 20.0
POSITION_MOVE_FLAG_PCT = 15.0
EXTREME_MOVE_PCT = 20.0
NEW_TOKEN_HOURS = 48
SYNTHETIC_MARKERS = ("x1L", "x2L", "x3L")

SESSION = requests.Session()


# ----------------------------------------------------------------------------
# base58 + ed25519 on-curve check, needed to derive Raydium's PersonalPositionState PDA
# ----------------------------------------------------------------------------
_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    num = 0
    for char in s.encode():
        num = num * 58 + _ALPHABET.index(char)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big")
    n_pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_pad + combined


def b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_ALPHABET[rem])
    n_pad = len(b) - len(b.lstrip(b"\x00"))
    return ("1" * n_pad) + out[::-1].decode()


_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _is_on_curve(pt: bytes) -> bool:
    if len(pt) != 32:
        return False
    y = int.from_bytes(pt, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False
    yy = (y * y) % _P
    xx = ((yy - 1) * pow((_D * yy + 1) % _P, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _SQRT_M1) % _P
    return (x * x - xx) % _P == 0


def find_program_address(seeds, program_id: str):
    program_bytes = b58decode(program_id)
    for bump in range(255, -1, -1):
        buf = b"".join(seeds) + bytes([bump]) + program_bytes + b"ProgramDerivedAddress"
        h = hashlib.sha256(buf).digest()
        if not _is_on_curve(h):
            return b58encode(h), bump
    raise ValueError("no off-curve PDA found")


# ----------------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------------
def http_get(url, headers=None, params=None, retries=5, timeout=30, backoff=3):
    last_exc = None
    for attempt in range(retries):
        try:
            r = SESSION.get(url, headers=headers, params=params, timeout=timeout)
            if r.status_code == 429:
                time.sleep(backoff * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            last_exc = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after {retries} attempts: {last_exc}")


_last_geckoterminal_call = [0.0]
_GECKOTERMINAL_MIN_INTERVAL = 1.3  # stay under the public API's rate limit


def _geckoterminal_pace():
    elapsed = time.monotonic() - _last_geckoterminal_call[0]
    if elapsed < _GECKOTERMINAL_MIN_INTERVAL:
        time.sleep(_GECKOTERMINAL_MIN_INTERVAL - elapsed)
    _last_geckoterminal_call[0] = time.monotonic()


def zerion_get(path, params=None):
    auth = base64.b64encode(f"{ZERION_API_KEY}:".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    return http_get(f"https://api.zerion.io/v1{path}", headers=headers, params=params)


def geckoterminal_get(path):
    _geckoterminal_pace()
    return http_get(f"https://api.geckoterminal.com/api/v2{path}", retries=6, backoff=4)


def coingecko_get(path, params=None):
    headers = {"x-cg-demo-api-key": COINGECKO_API_KEY}
    return http_get(f"https://api.coingecko.com/api/v3{path}", headers=headers, params=params)


def rpc_call(method, params):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_exc = None
    for attempt in range(4):
        r = SESSION.post(ALCHEMY_SOLANA_RPC, json=payload, timeout=30)
        try:
            data = r.json()
        except ValueError:
            data = {}
        if "error" in data:
            last_exc = data["error"]
            time.sleep(3 * (attempt + 1))
            continue
        return data.get("result")
    raise RuntimeError(f"RPC {method} failed: {last_exc}")


# ----------------------------------------------------------------------------
# Zerion: EVM (Robinhood chain) positions
# ----------------------------------------------------------------------------
def fetch_zerion_evm_positions():
    complex_data = zerion_get(
        f"/wallets/{EVM_WALLET}/positions/", params={"filter[positions]": "only_complex"}
    )
    simple_data = zerion_get(
        f"/wallets/{EVM_WALLET}/positions/", params={"filter[positions]": "only_simple"}
    )
    return complex_data.get("data", []), simple_data.get("data", [])


def group_robinhood_lp_positions(complex_positions):
    """Group per-leg Zerion 'deposit' rows into one row per LP position (by group_id)."""
    groups = {}
    for pos in complex_positions:
        attrs = pos["attributes"]
        if attrs.get("position_type") != "deposit":
            continue
        gid = attrs.get("group_id") or attrs.get("name")
        g = groups.setdefault(
            gid,
            {
                "name": attrs.get("name"),
                "protocol": attrs.get("protocol"),
                "value_usd": 0.0,
                "legs": [],
            },
        )
        g["value_usd"] += attrs.get("value") or 0.0
        fi = attrs.get("fungible_info", {})
        impl = next(
            (i for i in fi.get("implementations", []) if i.get("chain_id") == "robinhood"), None
        )
        g["legs"].append(
            {
                "symbol": fi.get("symbol"),
                "name": fi.get("name"),
                "verified": fi.get("flags", {}).get("verified"),
                "address": impl.get("address") if impl else None,
                "value_usd": attrs.get("value") or 0.0,
                "percent_1d": (attrs.get("changes") or {}).get("percent_1d"),
            }
        )
    return list(groups.values())


# ----------------------------------------------------------------------------
# GeckoTerminal: resolve a Zerion LP group to a specific pool, then fetch pool health
# ----------------------------------------------------------------------------
def extract_fee_tier(name):
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", name or "")
    return float(m.group(1)) if m else None


def resolve_robinhood_pool(group):
    """Best-effort match of a Zerion LP group to a concrete GeckoTerminal pool.
    Uses the token-pools search on the least-common leg (fewer candidate pools to
    disambiguate), then prefers an exact fee-tier match over the highest-TVL pool.
    Returns (pool_attributes, approximate: bool) or (None, False) if unresolved.
    """
    legs = [leg for leg in group["legs"] if leg["address"]]
    if len(legs) < 1:
        return None, False
    # probe with whichever leg has a shorter symbol name last (heuristic: majors like WETH/ETH
    # have far more pools than a project token, so query the *other* leg if there are two)
    probe_leg = legs[0]
    other_symbols = {l["symbol"].upper() for l in legs if l is not probe_leg}
    try:
        data = geckoterminal_get(f"/networks/robinhood/tokens/{probe_leg['address']}/pools")
    except RuntimeError:
        return None, False
    candidates = data.get("data", [])
    wanted_fee = extract_fee_tier(group["name"])
    best, best_approx = None, True
    for c in candidates:
        a = c["attributes"]
        pool_name = (a.get("name") or "").upper()
        if other_symbols and not any(sym in pool_name for sym in other_symbols):
            continue
        if wanted_fee is not None and extract_fee_tier(a.get("name")) == wanted_fee:
            return a, False  # exact fee-tier match
        tvl = float(a.get("reserve_in_usd") or 0)
        if best is None or tvl > float(best.get("reserve_in_usd") or 0):
            best = a
    return best, True


def fetch_pool_health(network, pool_address):
    data = geckoterminal_get(f"/networks/{network}/pools/{pool_address}")
    a = data["data"]["attributes"]
    rel = data["data"]["relationships"]
    base_id = ((rel.get("base_token") or {}).get("data") or {}).get("id", "")
    quote_id = ((rel.get("quote_token") or {}).get("data") or {}).get("id", "")
    pc = a.get("price_change_percentage") or {}
    return {
        "name": a.get("name"),
        "address": a.get("address"),
        "tvl_usd": float(a.get("reserve_in_usd") or 0),
        "volume_24h_usd": float((a.get("volume_usd") or {}).get("h24") or 0),
        "price_change_24h_pct": float(pc["h24"]) if pc.get("h24") not in (None, "") else None,
        "pool_created_at": a.get("pool_created_at"),
        "base_token_address": base_id.split("_", 1)[-1] if base_id else None,
        "quote_token_address": quote_id.split("_", 1)[-1] if quote_id else None,
        "base_token_price_usd": float(a["base_token_price_usd"]) if a.get("base_token_price_usd") else None,
        "quote_token_price_usd": float(a["quote_token_price_usd"]) if a.get("quote_token_price_usd") else None,
    }


def pool_age_hours(pool_created_at):
    if not pool_created_at:
        return None
    created = datetime.fromisoformat(pool_created_at.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - created).total_seconds() / 3600.0


# ----------------------------------------------------------------------------
# Raydium CLMM (Solana): find position NFTs owned by the wallet, derive the
# PersonalPositionState PDA, decode it directly from the account bytes, then
# decode the referenced PoolState to get the current tick / price.
# ----------------------------------------------------------------------------
def get_token_accounts(owner, program_id):
    result = rpc_call(
        "getTokenAccountsByOwner",
        [owner, {"programId": program_id}, {"encoding": "jsonParsed"}],
    )
    return result.get("value", []) if result else []


def find_position_nft_mints(owner):
    mints = []
    for program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        for acct in get_token_accounts(owner, program):
            info = acct["account"]["data"]["parsed"]["info"]
            amt = info["tokenAmount"]
            if amt["decimals"] == 0 and amt.get("uiAmount") == 1:
                mints.append(info["mint"])
    return mints


def get_account_bytes(address):
    result = rpc_call("getAccountInfo", [address, {"encoding": "base64"}])
    if not result or not result.get("value"):
        return None
    return base64.b64decode(result["value"]["data"][0])


PERSONAL_POSITION_DISC = hashlib.sha256(b"account:PersonalPositionState").digest()[:8]
POOL_STATE_DISC = hashlib.sha256(b"account:PoolState").digest()[:8]


def decode_personal_position(data):
    if data[:8] != PERSONAL_POSITION_DISC:
        return None
    off = 9  # skip discriminator(8) + bump(1)
    nft_mint = b58encode(data[off : off + 32]); off += 32
    pool_id = b58encode(data[off : off + 32]); off += 32
    tick_lower = struct.unpack("<i", data[off : off + 4])[0]; off += 4
    tick_upper = struct.unpack("<i", data[off : off + 4])[0]; off += 4
    liquidity = int.from_bytes(data[off : off + 16], "little")
    return {
        "nft_mint": nft_mint,
        "pool_id": pool_id,
        "tick_lower": tick_lower,
        "tick_upper": tick_upper,
        "liquidity": liquidity,
    }


def decode_pool_state(data):
    if data[:8] != POOL_STATE_DISC:
        return None
    off = 9 + 32 + 32  # discriminator(8)+bump(1)+amm_config(32)+owner(32)
    mint0 = b58encode(data[off : off + 32]); off += 32
    mint1 = b58encode(data[off : off + 32]); off += 32
    off += 32 + 32 + 32  # vault0, vault1, observation_key
    dec0 = data[off]; off += 1
    dec1 = data[off]; off += 1
    off += 2  # tick_spacing
    off += 16  # liquidity
    sqrt_price_x64 = int.from_bytes(data[off : off + 16], "little"); off += 16
    tick_current = struct.unpack("<i", data[off : off + 4])[0]
    return {
        "mint0": mint0,
        "mint1": mint1,
        "dec0": dec0,
        "dec1": dec1,
        "sqrt_price_x64": sqrt_price_x64,
        "tick_current": tick_current,
    }


def tick_to_sqrt_price_x64(tick):
    return int((1.0001 ** (tick / 2.0)) * (2**64))


def clmm_token_amounts(liquidity, sqrt_price_current_x64, tick_lower, tick_upper, dec0, dec1):
    L = liquidity
    sp_lower = tick_to_sqrt_price_x64(tick_lower)
    sp_upper = tick_to_sqrt_price_x64(tick_upper)
    sp_cur = sqrt_price_current_x64
    Q64 = 2**64
    if sp_cur <= sp_lower:
        amount0 = L * (Q64 / sp_lower - Q64 / sp_upper)
        amount1 = 0
    elif sp_cur >= sp_upper:
        amount0 = 0
        amount1 = L * (sp_upper - sp_lower) / Q64
    else:
        amount0 = L * (Q64 / sp_cur - Q64 / sp_upper)
        amount1 = L * (sp_cur - sp_lower) / Q64
    return amount0 / (10**dec0), amount1 / (10**dec1)


def fetch_raydium_positions():
    positions = []
    for mint in find_position_nft_mints(SOL_WALLET):
        pda, _bump = find_program_address([b"position", b58decode(mint)], RAYDIUM_CLMM_PROGRAM)
        raw = get_account_bytes(pda)
        if not raw:
            continue
        pos = decode_personal_position(raw)
        if not pos or pos["liquidity"] == 0:
            continue
        pool_raw = get_account_bytes(pos["pool_id"])
        pool = decode_pool_state(pool_raw) if pool_raw else None
        if not pool:
            continue
        amt0, amt1 = clmm_token_amounts(
            pos["liquidity"],
            pool["sqrt_price_x64"],
            pos["tick_lower"],
            pos["tick_upper"],
            pool["dec0"],
            pool["dec1"],
        )
        in_range = pos["tick_lower"] <= pool["tick_current"] <= pos["tick_upper"]
        positions.append(
            {
                "nft_mint": pos["nft_mint"],
                "pool_id": pos["pool_id"],
                "mint0": pool["mint0"],
                "mint1": pool["mint1"],
                "amount0": amt0,
                "amount1": amt1,
                "tick_lower": pos["tick_lower"],
                "tick_upper": pos["tick_upper"],
                "tick_current": pool["tick_current"],
                "in_range": in_range,
            }
        )
    return positions


# ----------------------------------------------------------------------------
# CoinGecko: price cross-check for major assets
# ----------------------------------------------------------------------------
def coingecko_simple_price(ids):
    if not ids:
        return {}
    data = coingecko_get(
        "/simple/price",
        params={
            "ids": ",".join(sorted(set(ids))),
            "vs_currencies": "usd",
            "include_24hr_change": "true",
        },
    )
    return data


def coingecko_cross_check(platform, contract_address):
    """Second-source cross-check for an extreme move. Returns 24h % change or None
    if the token isn't listed on CoinGecko (common for very new / obscure tokens)."""
    try:
        data = coingecko_get(f"/coins/{platform}/contract/{contract_address}")
        return (data.get("market_data") or {}).get("price_change_percentage_24h")
    except RuntimeError:
        return None


# ----------------------------------------------------------------------------
# Aggregation: build one flat list of "instruments" (pools/positions) to run
# the risk checks over, each tagged with where every number came from.
# ----------------------------------------------------------------------------
def build_instruments(evm_complex, evm_simple, sol_simple, raydium_positions):
    instruments = []

    for group in group_robinhood_lp_positions(evm_complex):
        pool_attrs, approx = resolve_robinhood_pool(group)
        health = None
        if pool_attrs is not None:
            try:
                health = fetch_pool_health("robinhood", pool_attrs["address"])
            except RuntimeError:
                health = None
        instruments.append(
            {
                "label": f"{group['name']} (Robinhood)",
                "chain": "robinhood",
                "value_usd": group["value_usd"],
                "legs": group["legs"],
                "health": health,
                "pool_match_approximate": approx,
                "pool_source": "GeckoTerminal",
            }
        )

    for pos in raydium_positions:
        try:
            health = fetch_pool_health("solana", pos["pool_id"])
        except RuntimeError:
            health = None
        value_usd = None
        legs = [
            {"symbol": None, "address": pos["mint0"], "verified": None, "percent_1d": None},
            {"symbol": None, "address": pos["mint1"], "verified": None, "percent_1d": None},
        ]
        if health:
            if health["base_token_address"] == pos["mint0"]:
                price0, price1 = health["base_token_price_usd"], health["quote_token_price_usd"]
            else:
                price0, price1 = health["quote_token_price_usd"], health["base_token_price_usd"]
            if price0 is not None and price1 is not None:
                value_usd = pos["amount0"] * price0 + pos["amount1"] * price1
        instruments.append(
            {
                "label": f"Raydium CLMM {pos['nft_mint'][:6]}... "
                f"({'in range' if pos['in_range'] else 'OUT OF RANGE'})",
                "chain": "solana",
                "value_usd": value_usd,
                "legs": legs,
                "health": health,
                "pool_match_approximate": False,
                "pool_source": "Raydium/Solana RPC decode + GeckoTerminal",
                "raydium_detail": pos,
            }
        )

    return instruments


def evaluate_flags(instruments):
    flags = []

    for inst in instruments:
        h = inst.get("health")
        if not h:
            flags.append(
                {
                    "severity": "info",
                    "message": f"{inst['label']}: could not resolve pool health data "
                    f"(no GeckoTerminal match found) — reported value/PnL for this "
                    f"position may be incomplete.",
                }
            )
            continue

        if h["volume_24h_usd"] <= VOLUME_FLAG_THRESHOLD_USD:
            flags.append(
                {
                    "severity": "high",
                    "message": f"{inst['label']}: $0 24h volume "
                    f"[GeckoTerminal, pool {h['address']}]",
                }
            )

        if inst["value_usd"] and h["tvl_usd"]:
            share_pct = 100.0 * inst["value_usd"] / h["tvl_usd"]
            if share_pct > POOL_SHARE_FLAG_PCT:
                flags.append(
                    {
                        "severity": "high",
                        "message": f"{inst['label']}: your position is "
                        f"{share_pct:.1f}% of total pool TVL "
                        f"(position ${inst['value_usd']:,.2f} [Zerion/Raydium], "
                        f"pool TVL ${h['tvl_usd']:,.2f} [GeckoTerminal])",
                    }
                )

        move = h.get("price_change_24h_pct")
        if move is not None and abs(move) > POSITION_MOVE_FLAG_PCT:
            age_h = pool_age_hours(h.get("pool_created_at"))
            note = ""
            if abs(move) > EXTREME_MOVE_PCT and age_h is not None and age_h < NEW_TOKEN_HOURS:
                base_addr = h.get("base_token_address")
                cross = coingecko_cross_check("robinhood" if inst["chain"] == "robinhood" else "solana", base_addr) if base_addr else None
                if cross is None:
                    note = " — UNVERIFIED: token/pool is <48h old and no second source " \
                           "was available to cross-check this move; treat with caution."
                elif abs(cross - move) > 10:
                    note = f" — cross-check via CoinGecko shows {cross:.1f}%, " \
                           f"materially different; treat with caution."
                else:
                    note = f" — cross-checked via CoinGecko ({cross:.1f}%), consistent."
            flags.append(
                {
                    "severity": "high" if abs(move) > EXTREME_MOVE_PCT else "medium",
                    "message": f"{inst['label']}: pool price moved {move:+.1f}% in 24h "
                    f"[GeckoTerminal]{note}",
                }
            )

        for leg in inst["legs"]:
            p1d = leg.get("percent_1d")
            if p1d is not None and abs(p1d) > POSITION_MOVE_FLAG_PCT:
                flags.append(
                    {
                        "severity": "medium",
                        "message": f"{inst['label']} / {leg.get('symbol')}: "
                        f"{p1d:+.1f}% over 1d [Zerion]",
                    }
                )
            name_blob = f"{leg.get('symbol') or ''} {leg.get('name') or ''}"
            if any(marker in name_blob for marker in SYNTHETIC_MARKERS):
                flags.append(
                    {
                        "severity": "high",
                        "message": f"{inst['label']} / {leg.get('symbol')}: name pattern "
                        f"suggests a synthetic/leveraged derivative — do not treat as the "
                        f"underlying asset [Zerion token metadata].",
                    }
                )
            if leg.get("verified") is False:
                flags.append(
                    {
                        "severity": "medium",
                        "message": f"{inst['label']} / {leg.get('symbol')}: token is "
                        f"UNVERIFIED per Zerion's token registry [Zerion].",
                    }
                )

    # Cross-pool identical-move red flag: same token symbol, 2+ pools, near-identical 24h move.
    by_symbol = {}
    for inst in instruments:
        h = inst.get("health")
        if not h or h.get("price_change_24h_pct") is None:
            continue
        for leg in inst["legs"]:
            sym = (leg.get("symbol") or "").upper()
            if sym:
                by_symbol.setdefault(sym, []).append((inst["label"], h["price_change_24h_pct"]))
    for sym, entries in by_symbol.items():
        if len(entries) < 2:
            continue
        values = [v for _, v in entries]
        if max(values) - min(values) < 0.05:
            labels = ", ".join(l for l, _ in entries)
            flags.append(
                {
                    "severity": "medium",
                    "message": f"{sym}: {len(entries)} pools ({labels}) show suspiciously "
                    f"identical 24h moves ({values[0]:+.2f}%) — re-verify before trusting "
                    f"this figure [GeckoTerminal].",
                }
            )

    return flags


# ----------------------------------------------------------------------------
# Snapshot persistence + trend comparison
# ----------------------------------------------------------------------------
def load_previous_snapshot():
    if not os.path.exists(SNAPSHOT_PATH):
        return None
    try:
        with open(SNAPSHOT_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_snapshot(snapshot):
    os.makedirs(os.path.dirname(SNAPSHOT_PATH) or ".", exist_ok=True)
    with open(SNAPSHOT_PATH, "w") as f:
        json.dump(snapshot, f, indent=2)


def compare_to_previous(current_total, current_instruments, previous):
    lines = []
    if not previous:
        lines.append("No previous snapshot available yet — this is the first recorded check, "
                      "so no continuing/reversing trend can be determined.")
        return lines
    prev_total = previous.get("total_value_usd")
    if prev_total:
        delta = current_total - prev_total
        pct = 100.0 * delta / prev_total if prev_total else 0
        lines.append(
            f"Total value vs previous check: {delta:+,.2f} USD ({pct:+.2f}%), "
            f"previous check at {previous.get('timestamp')}"
        )
    prev_by_label = {i["label"]: i for i in previous.get("instruments", [])}
    for inst in current_instruments:
        prev_inst = prev_by_label.get(inst["label"])
        h = inst.get("health") or {}
        move = h.get("price_change_24h_pct")
        if prev_inst is None or move is None:
            continue
        prev_move = (prev_inst.get("health") or {}).get("price_change_24h_pct")
        if prev_move is None:
            continue
        if (move > 0) == (prev_move > 0) and abs(move) >= abs(prev_move):
            trend = "continuing"
        elif (move > 0) != (prev_move > 0):
            trend = "reversing"
        else:
            trend = "decelerating"
        if abs(move) > POSITION_MOVE_FLAG_PCT or abs(prev_move) > POSITION_MOVE_FLAG_PCT:
            lines.append(
                f"{inst['label']}: {prev_move:+.1f}% -> {move:+.1f}% ({trend}) "
                f"[GeckoTerminal, this check vs previous]"
            )
    return lines


# ----------------------------------------------------------------------------
# Summary + email
# ----------------------------------------------------------------------------
def build_summary(now, evm_total, evm_pnl_1d, sol_total, sol_pnl_1d, instruments, flags, trend_lines, major_prices):
    total = evm_total + sol_total
    pnl = evm_pnl_1d + sol_pnl_1d
    lines = []
    lines.append(f"DeFi Pulse — {now.strftime('%Y-%m-%d %H:%M %Z')}")
    lines.append("")
    lines.append(f"Total portfolio value: ${total:,.2f} [Zerion + Raydium/Solana RPC + GeckoTerminal]")
    lines.append(f"Today's PnL (reported, Zerion 1d changes): {pnl:+,.2f} USD")
    lines.append(f"  EVM (Robinhood chain) value: ${evm_total:,.2f} [Zerion]")
    lines.append(f"  Solana value (wallet + Raydium LP): ${sol_total:,.2f} "
                  f"[Zerion for wallet balances; Raydium/Solana RPC decode + GeckoTerminal pricing for LP]")
    lines.append("")

    if major_prices:
        parts = []
        for coin_id, label in (("ethereum", "ETH"), ("solana", "SOL")):
            p = major_prices.get(coin_id, {}).get("usd")
            if p is not None:
                parts.append(f"{label} ${p:,.2f}")
        if parts:
            lines.append("Reference prices: " + ", ".join(parts) + " [CoinGecko]")
            lines.append("")

    raydium_insts = [i for i in instruments if "raydium_detail" in i]
    if raydium_insts:
        lines.append("Raydium position(s):")
        for inst in raydium_insts:
            d = inst["raydium_detail"]
            val = f"${inst['value_usd']:,.2f}" if inst["value_usd"] is not None else "unknown"
            lines.append(
                f"  - {inst['label']}: value {val}, ticks [{d['tick_lower']}, {d['tick_upper']}], "
                f"current tick {d['tick_current']} [Raydium/Solana RPC decode]"
            )
        lines.append("")

    high_flags = [f for f in flags if f["severity"] == "high"]
    med_flags = [f for f in flags if f["severity"] == "medium"]
    if high_flags:
        lines.append("HIGH-RISK FLAGS:")
        for f in high_flags:
            lines.append(f"  - {f['message']}")
        lines.append("")
    if med_flags:
        lines.append("Other flags:")
        for f in med_flags:
            lines.append(f"  - {f['message']}")
        lines.append("")

    lines.append("Trend vs previous check:")
    if trend_lines:
        for t in trend_lines:
            lines.append(f"  - {t}")
    else:
        lines.append("  - No positions currently exceed the 15% move threshold.")

    return "\n".join(lines)


def send_email(subject, body):
    to_addr = os.environ["ALERT_EMAIL_TO"]
    smtp_user = os.environ["GMAIL_SMTP_USER"]
    smtp_pass = os.environ["GMAIL_SMTP_APP_PASSWORD"]
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_addr
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [to_addr], msg.as_string())


# ----------------------------------------------------------------------------
def main():
    now = datetime.now(timezone.utc)

    evm_complex, evm_simple = fetch_zerion_evm_positions()
    evm_total = sum((p["attributes"].get("value") or 0) for p in evm_complex + evm_simple)
    evm_pnl_1d = sum(((p["attributes"].get("changes") or {}).get("absolute_1d") or 0) for p in evm_complex + evm_simple)

    sol_simple_data = zerion_get(f"/wallets/{SOL_WALLET}/positions/", params={"filter[positions]": "only_simple"})
    sol_simple = sol_simple_data.get("data", [])
    sol_wallet_total = sum((p["attributes"].get("value") or 0) for p in sol_simple)
    sol_wallet_pnl_1d = sum(((p["attributes"].get("changes") or {}).get("absolute_1d") or 0) for p in sol_simple)

    raydium_positions = fetch_raydium_positions()
    instruments = build_instruments(evm_complex, evm_simple, sol_simple, raydium_positions)

    raydium_value_total = sum(i["value_usd"] or 0 for i in instruments if "raydium_detail" in i)
    raydium_pnl_1d = sum(
        (i["value_usd"] or 0) * (i["health"]["price_change_24h_pct"] / 100.0)
        for i in instruments
        if "raydium_detail" in i and i.get("health") and i["health"].get("price_change_24h_pct") is not None
    )

    sol_total = sol_wallet_total + raydium_value_total
    sol_pnl_1d = sol_wallet_pnl_1d + raydium_pnl_1d
    total = evm_total + sol_total

    flags = evaluate_flags(instruments)

    previous = load_previous_snapshot()
    trend_lines = compare_to_previous(total, instruments, previous)

    try:
        major_prices = coingecko_simple_price(["ethereum", "solana"])
    except RuntimeError:
        major_prices = {}

    summary = build_summary(now, evm_total, evm_pnl_1d, sol_total, sol_pnl_1d, instruments, flags, trend_lines, major_prices)
    print(summary)

    snapshot = {
        "timestamp": now.isoformat(),
        "total_value_usd": total,
        "instruments": [
            {
                "label": i["label"],
                "value_usd": i["value_usd"],
                "health": i.get("health"),
            }
            for i in instruments
        ],
    }
    save_snapshot(snapshot)

    if os.environ.get("SKIP_EMAIL") != "1":
        high_count = len([f for f in flags if f["severity"] == "high"])
        subject = f"DeFi Pulse — ${total:,.0f} total"
        if high_count:
            subject += f" — {high_count} high-risk flag(s)"
        send_email(subject, summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())

