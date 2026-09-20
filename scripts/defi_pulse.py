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
from Crypto.Hash import keccak

EVM_WALLET = os.environ.get("EVM_WALLET", "0x889e1cd896f611a3cba990fce8dbd54802f904e2")
SOL_WALLET = os.environ.get("SOL_WALLET", "EghVz6qV3bGEAX85SQc38htEZiorou9TJxCcWpfHsa9U")

ZERION_API_KEY = os.environ["ZERION_API_KEY"]
COINGECKO_API_KEY = os.environ["COINGECKO_API_KEY"]
ALCHEMY_SOLANA_RPC = os.environ.get(
    "ALCHEMY_SOLANA_RPC",
    "https://solana-mainnet.g.alchemy.com/v2/" + os.environ.get("ALCHEMY_API_KEY", ""),
)
ROBINHOOD_RPC = os.environ.get("ROBINHOOD_RPC", "https://rpc.mainnet.chain.robinhood.com")
BITQUERY_TOKEN = os.environ.get("BITQUERY_TOKEN")

RAYDIUM_CLMM_PROGRAM = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# Robinhood chain (EVM) Uniswap contracts. The v4 PoolManager is the core singleton and does
# NOT implement ERC-721 (no balanceOf/tokenOfOwnerByIndex) — positions are owned via the
# separate v4 Positions NFT periphery contract. Both addresses below were validated live:
# V3 positions() decode was cross-checked 1:1 against Zerion's reported V3 pools, and the v4
# PoolManager slot math was validated by recomputing a known position's poolId + tick range.
V3_POSITION_MANAGER = "0x73991a25c818bf1f1128deaab1492d45638de0d3"
V4_POSITIONS_NFT = "0x58daec3116aae6d93017baaea7749052e8a04fa7"
V4_POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
POOLS_STORAGE_SLOT = (6).to_bytes(32, "big")  # v4-core PoolManager: `pools` mapping is slot 6

SNAPSHOT_PATH = os.environ.get("SNAPSHOT_PATH", "data/last_snapshot.json")

VOLUME_FLAG_THRESHOLD_USD = 0.0
POOL_SHARE_FLAG_PCT = 20.0
POSITION_MOVE_FLAG_PCT = 15.0
EXTREME_MOVE_PCT = 20.0
NEW_TOKEN_HOURS = 48
SYNTHETIC_MARKERS = ("x1L", "x2L", "x3L")
TOP_POOL_TVL_FLOOR_USD = 1_000_000.0

# Confirmed-scam mints/addresses (Solana mint or EVM address). Any wallet holding matching
# one of these is flagged regardless of value or other checks.
KNOWN_SCAM_ADDRESSES = {
    "AGpTKe9N2qFcPuGyYqvWCugoZSvg6g1RDTBAm6mtCF5g": "fake HYPE",
    "3oiHhk2PpwMvfrA7yFtXTNCM62AZnwVDxaANMFa6ufhz": 'fake "OnRe Tokenized Reinsurance"',
    "7gZnpmL72hvjp6WUde8viTKVbMAhMsSHsqxh95JBsLpq": "fake PayPal USD",
}

SESSION = requests.Session()


def keccak_selector(signature):
    return keccak.new(data=signature.encode(), digest_bits=256).digest()[:4]


def keccak256(data):
    return keccak.new(data=data, digest_bits=256).digest()


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


def evm_rpc_call(method, params, retries=4):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_exc = None
    for attempt in range(retries):
        r = SESSION.post(ROBINHOOD_RPC, json=payload, timeout=30)
        try:
            data = r.json()
        except ValueError:
            data = {}
        if "error" in data:
            last_exc = data["error"]
            time.sleep(3 * (attempt + 1))
            continue
        return data.get("result")
    raise RuntimeError(f"Robinhood RPC {method} failed: {last_exc}")


def eth_call(to, data):
    return evm_rpc_call("eth_call", [{"to": to, "data": data}, "latest"])


def eth_call_int(to, data):
    r = eth_call(to, data)
    return int(r, 16) if r and r != "0x" else None


_decimals_cache = {}


def erc20_decimals(token_address):
    if token_address not in _decimals_cache:
        r = eth_call(token_address, "0x313ce567")  # decimals()
        _decimals_cache[token_address] = int(r, 16) if r and r != "0x" else 18
    return _decimals_cache[token_address]


def _pad_addr(addr):
    return addr[2:].rjust(64, "0")


def _pad_uint(n):
    return format(n & ((1 << 256) - 1), "064x")


def _to_signed(x, bits):
    return x - (1 << bits) if x & (1 << (bits - 1)) else x


# ----------------------------------------------------------------------------
# Robinhood chain (EVM) direct decode: cross-checks / supplements Zerion.
# Uniswap v3 positions are fully enumerable (ERC721Enumerable). v4 positions are NOT
# enumerable on-chain, so we reconstruct current ownership from Transfer event logs.
# ----------------------------------------------------------------------------
def fetch_v3_positions_onchain(wallet):
    bal = eth_call_int(V3_POSITION_MANAGER, "0x70a08231" + _pad_addr(wallet))
    if not bal:
        return []
    positions = []
    for i in range(bal):
        tid_r = eth_call(V3_POSITION_MANAGER, "0x2f745c59" + _pad_addr(wallet) + _pad_uint(i))
        token_id = int(tid_r, 16)
        raw = eth_call(V3_POSITION_MANAGER, "0x99fbab88" + _pad_uint(token_id))
        data = bytes.fromhex(raw[2:])
        words = [data[j * 32 : (j + 1) * 32] for j in range(len(data) // 32)]
        liquidity = int.from_bytes(words[7], "big")
        if liquidity == 0:
            continue
        positions.append(
            {
                "token_id": token_id,
                "token0": "0x" + words[2][-20:].hex(),
                "token1": "0x" + words[3][-20:].hex(),
                "fee": int.from_bytes(words[4], "big"),
                "tick_lower": _to_signed(int.from_bytes(words[5], "big"), 256),
                "tick_upper": _to_signed(int.from_bytes(words[6], "big"), 256),
                "liquidity": liquidity,
                "version": "v3",
            }
        )
    return positions


def _current_v4_token_ids(wallet):
    received = evm_rpc_call(
        "eth_getLogs",
        [{"address": V4_POSITIONS_NFT, "fromBlock": "0x0", "toBlock": "latest",
          "topics": [TRANSFER_TOPIC, None, "0x" + _pad_addr(wallet)]}],
    )
    sent = evm_rpc_call(
        "eth_getLogs",
        [{"address": V4_POSITIONS_NFT, "fromBlock": "0x0", "toBlock": "latest",
          "topics": [TRANSFER_TOPIC, "0x" + _pad_addr(wallet)]}],
    )
    held = {}
    for log in received:
        tid = int(log["topics"][3], 16)
        held[tid] = int(log["blockNumber"], 16)
    for log in sent:
        tid = int(log["topics"][3], 16)
        sent_block = int(log["blockNumber"], 16)
        if tid in held and sent_block >= held[tid]:
            del held[tid]
    return list(held.keys())


def compute_v4_pool_id(currency0, currency1, fee, tick_spacing, hooks):
    packed = (
        bytes.fromhex(_pad_addr(currency0))
        + bytes.fromhex(_pad_addr(currency1))
        + bytes.fromhex(_pad_uint(fee))
        + bytes.fromhex(_pad_uint(tick_spacing & ((1 << 256) - 1)))
        + bytes.fromhex(_pad_addr(hooks))
    )
    return keccak256(packed)


def fetch_v4_pool_slot0(pool_id_bytes):
    state_slot = keccak256(pool_id_bytes + POOLS_STORAGE_SLOT)
    raw = eth_call(V4_POOL_MANAGER, "0x1e2eaeaf" + state_slot.hex())
    data = int(raw, 16)
    sqrt_price_x96 = data & ((1 << 160) - 1)
    tick = _to_signed((data >> 160) & 0xFFFFFF, 24)
    return sqrt_price_x96, tick


def fetch_v4_positions_onchain(wallet):
    positions = []
    for token_id in _current_v4_token_ids(wallet):
        liq_r = eth_call(V4_POSITIONS_NFT, "0x1efeed33" + _pad_uint(token_id))
        liquidity = int(liq_r, 16) if liq_r and liq_r != "0x" else 0
        if liquidity == 0:
            continue
        raw = eth_call(V4_POSITIONS_NFT, "0x7ba03aad" + _pad_uint(token_id))
        data = bytes.fromhex(raw[2:])
        words = [data[j * 32 : (j + 1) * 32] for j in range(len(data) // 32)]
        currency0 = "0x" + words[0][-20:].hex()
        currency1 = "0x" + words[1][-20:].hex()
        fee = int.from_bytes(words[2], "big")
        tick_spacing = _to_signed(int.from_bytes(words[3], "big"), 256)
        hooks = "0x" + words[4][-20:].hex()
        info = int.from_bytes(words[5], "big")
        tick_lower = _to_signed((info >> 8) & 0xFFFFFF, 24)
        tick_upper = _to_signed((info >> 32) & 0xFFFFFF, 24)
        pool_id = compute_v4_pool_id(currency0, currency1, fee, tick_spacing, hooks)
        positions.append(
            {
                "token_id": token_id,
                "token0": currency0,
                "token1": currency1,
                "fee": fee,
                "tick_spacing": tick_spacing,
                "hooks": hooks,
                "tick_lower": tick_lower,
                "tick_upper": tick_upper,
                "liquidity": liquidity,
                "pool_id": "0x" + pool_id.hex(),
                "version": "v4",
            }
        )
    return positions


def tick_to_sqrtp_q96(tick):
    return int((1.0001 ** (tick / 2.0)) * (2**96))


def evm_clmm_token_amounts(liquidity, sqrt_price_current_q96, tick_lower, tick_upper, dec0, dec1):
    L = liquidity
    sp_lower = tick_to_sqrtp_q96(tick_lower)
    sp_upper = tick_to_sqrtp_q96(tick_upper)
    sp_cur = sqrt_price_current_q96
    Q96 = 2**96
    if sp_cur <= sp_lower:
        amount0 = L * (Q96 / sp_lower - Q96 / sp_upper)
        amount1 = 0
    elif sp_cur >= sp_upper:
        amount0 = 0
        amount1 = L * (sp_upper - sp_lower) / Q96
    else:
        amount0 = L * (Q96 / sp_cur - Q96 / sp_upper)
        amount1 = L * (sp_cur - sp_lower) / Q96
    return amount0 / (10**dec0), amount1 / (10**dec1)


def fetch_onchain_robinhood_positions(wallet):
    """Ground-truth position discovery via direct RPC decode, used to catch anything
    Zerion's indexer misses (confirmed to happen for some v4 positions)."""
    positions = fetch_v3_positions_onchain(wallet)
    positions += fetch_v4_positions_onchain(wallet)
    return positions


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
        nft_info = attrs.get("receipt", {}).get("nft_info") or {}
        g = groups.setdefault(
            gid,
            {
                "name": attrs.get("name"),
                "protocol": attrs.get("protocol"),
                "value_usd": 0.0,
                "legs": [],
                "nft_token_id": int(nft_info["token_id"]) if nft_info.get("token_id") else None,
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
                "scam_flags": [
                    f"CONFIRMED SCAM ({KNOWN_SCAM_ADDRESSES[(impl or {}).get('address')]})"
                ] if (impl or {}).get("address") in KNOWN_SCAM_ADDRESSES else [],
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


def all_solana_token_balances(owner):
    """Every SPL/Token-2022 balance the wallet holds, including dust/spam tokens that
    Zerion's `only_simple` listing filters out as trash — that's exactly where a
    scam airdrop token sits, so the blocklist check needs to see these too."""
    balances = []
    for program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        for acct in get_token_accounts(owner, program):
            info = acct["account"]["data"]["parsed"]["info"]
            amt = info["tokenAmount"]
            ui_amount = amt.get("uiAmount") or 0
            if ui_amount > 0:
                balances.append({"mint": info["mint"], "amount": ui_amount})
    return balances


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
# Scam / risk screening (Solana): Jupiter's isSus audit flag + RugCheck holder
# concentration, plus a hardcoded blocklist of addresses already confirmed as scams.
# ----------------------------------------------------------------------------
def jupiter_token_info(mint):
    try:
        data = http_get(f"https://lite-api.jup.ag/tokens/v2/search?query={mint}", retries=2)
    except RuntimeError:
        return None
    return data[0] if data else None


def rugcheck_report(mint):
    try:
        return http_get(f"https://api.rugcheck.xyz/v1/tokens/{mint}/report", retries=2)
    except RuntimeError:
        return None


def screen_solana_token(mint):
    """Returns a list of risk-flag message strings for a Solana mint, or [] if clean.
    Checked (in order): hardcoded confirmed-scam list, Jupiter isSus, RugCheck top-holder
    concentration. Never asserts a token is 'safe' — absence of a red flag here is not
    a recommendation, only the absence of a detected one."""
    flags = []
    if mint in KNOWN_SCAM_ADDRESSES:
        flags.append(f"{mint} is a CONFIRMED SCAM ({KNOWN_SCAM_ADDRESSES[mint]}) — do not hold/trade.")
        return flags
    jup = jupiter_token_info(mint)
    if jup and (jup.get("audit") or {}).get("isSus"):
        flags.append(f"{mint} ({jup.get('symbol')}): Jupiter audit flags isSus=true [Jupiter].")
    rug = rugcheck_report(mint)
    if rug:
        top_holders = rug.get("topHolders") or []
        top_pct = top_holders[0]["pct"] if top_holders else None
        if top_pct is not None and top_pct > 50:
            flags.append(
                f"{mint} ({rug.get('tokenMeta', {}).get('symbol')}): top holder controls "
                f"{top_pct:.1f}% of supply — high rug risk [RugCheck]."
            )
    return flags


def screen_synthetic_derivative(symbol, name):
    blob = f"{symbol or ''} {name or ''}"
    return any(marker in blob for marker in SYNTHETIC_MARKERS)


# ----------------------------------------------------------------------------
# Monetize formula: score = 24h_volume * 24h_fees / TVL; aprDay = (24h_fees*365/TVL)*100
# ----------------------------------------------------------------------------
def monetize_metrics(volume_24h_usd, fees_24h_usd, tvl_usd):
    if not tvl_usd:
        return None
    score = volume_24h_usd * fees_24h_usd / tvl_usd
    apr_day = (fees_24h_usd * 365 / tvl_usd) * 100
    return {"score": score, "apr_day": apr_day, "fees_24h_usd": fees_24h_usd}


def robinhood_pool_fees_24h(pool_name, volume_24h_usd):
    fee_pct = extract_fee_tier(pool_name)
    if fee_pct is None:
        return None  # dynamic-fee pool or fee tier not embedded in the name — not guessed
    return volume_24h_usd * (fee_pct / 100.0)


def top_fee_pools_robinhood(pages=3):
    """Scan the top Robinhood-chain pools by GeckoTerminal's default (volume) sort,
    compute Monetize fees for each (fee tier parsed from name; dynamic-fee pools are
    skipped since the fee isn't knowable from this endpoint), screen out synthetic
    derivatives and sub-$1M-TVL pools, and return the top 3 by 24h fees generated."""
    seen = {}
    for page in range(1, pages + 1):
        try:
            data = geckoterminal_get(f"/networks/robinhood/pools?page={page}")
        except RuntimeError:
            break
        for p in data.get("data", []):
            a = p["attributes"]
            addr = a.get("address")
            if not addr or addr in seen:
                continue
            name = a.get("name") or ""
            if screen_synthetic_derivative(name, ""):
                continue
            tvl = float(a.get("reserve_in_usd") or 0)
            if tvl < TOP_POOL_TVL_FLOOR_USD:
                continue
            vol = float((a.get("volume_usd") or {}).get("h24") or 0)
            fees = robinhood_pool_fees_24h(name, vol)
            if fees is None:
                continue
            seen[addr] = {"name": name, "address": addr, "tvl_usd": tvl, "volume_24h_usd": vol,
                          "fees_24h_usd": fees, "apr_day": (fees * 365 / tvl) * 100}
    return sorted(seen.values(), key=lambda x: x["fees_24h_usd"], reverse=True)[:3]


def find_zerion_untracked_positions(zerion_groups):
    """Cross-check Zerion's reported Robinhood-chain LP positions against a direct RPC
    decode of the actual v3/v4 NFT position managers. Zerion has been confirmed (live,
    2026-09-20) to silently omit at least one active v4 position — this exists so a gap
    like that shows up in the report instead of being silently under-counted."""
    onchain = fetch_onchain_robinhood_positions(EVM_WALLET)
    tracked_token_ids = {g["nft_token_id"] for g in zerion_groups if g.get("nft_token_id")}
    return [p for p in onchain if p["token_id"] not in tracked_token_ids]


def build_untracked_instrument(pos):
    dec0 = erc20_decimals(pos["token0"]) if int(pos["token0"], 16) != 0 else 18
    dec1 = erc20_decimals(pos["token1"]) if int(pos["token1"], 16) != 0 else 18
    pool_address = None
    tick_current = None
    amt0 = amt1 = None
    if pos["version"] == "v4":
        pool_address = pos["pool_id"]
        sqrt_price, tick_current = fetch_v4_pool_slot0(bytes.fromhex(pool_address[2:]))
        amt0, amt1 = evm_clmm_token_amounts(
            pos["liquidity"], sqrt_price, pos["tick_lower"], pos["tick_upper"], dec0, dec1
        )
    # v3 pool address needs factory CREATE2 computation (not implemented — no observed gap
    # here since RPC-decoded v3 positions matched Zerion's reported set exactly); if this
    # ever fires, value/range are left unknown rather than guessed.

    health = None
    value_usd = None
    if pool_address:
        try:
            health = fetch_pool_health("robinhood", pool_address)
        except RuntimeError:
            health = None
        if health and amt0 is not None:
            if health["base_token_address"].lower() == pos["token0"].lower():
                price0, price1 = health["base_token_price_usd"], health["quote_token_price_usd"]
            else:
                price0, price1 = health["quote_token_price_usd"], health["base_token_price_usd"]
            if price0 is not None and price1 is not None:
                value_usd = amt0 * price0 + amt1 * price1

    range_note = ""
    if tick_current is not None:
        in_range = pos["tick_lower"] <= tick_current <= pos["tick_upper"]
        range_note = " (in range)" if in_range else " (OUT OF RANGE)"
    return {
        "label": f"UNTRACKED BY ZERION — {pos['version']} NFT #{pos['token_id']} "
        f"(Robinhood){range_note}",
        "chain": "robinhood",
        "value_usd": value_usd,
        "legs": [
            {"symbol": None, "name": None, "verified": None, "address": pos["token0"], "percent_1d": None},
            {"symbol": None, "name": None, "verified": None, "address": pos["token1"], "percent_1d": None},
        ],
        "health": health,
        "pool_match_approximate": False,
        "pool_source": "Robinhood Chain RPC direct decode (Zerion does not report this position)",
        "untracked_by_zerion": True,
        "onchain_detail": pos,
    }


# ----------------------------------------------------------------------------
# Aggregation: build one flat list of "instruments" (pools/positions) to run
# the risk checks over, each tagged with where every number came from.
# ----------------------------------------------------------------------------
def build_instruments(evm_complex, evm_simple, sol_simple, raydium_positions):
    instruments = []

    zerion_groups = group_robinhood_lp_positions(evm_complex)
    try:
        untracked = find_zerion_untracked_positions(zerion_groups)
    except RuntimeError:
        untracked = []
    for pos in untracked:
        try:
            instruments.append(build_untracked_instrument(pos))
        except RuntimeError:
            instruments.append(
                {
                    "label": f"UNTRACKED BY ZERION — {pos['version']} NFT #{pos['token_id']} "
                    f"(Robinhood) — value could not be computed, verify manually",
                    "chain": "robinhood",
                    "value_usd": None,
                    "legs": [],
                    "health": None,
                    "pool_match_approximate": False,
                    "pool_source": "Robinhood Chain RPC direct decode",
                    "untracked_by_zerion": True,
                    "onchain_detail": pos,
                }
            )

    for group in zerion_groups:
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
        legs = []
        for mint in (pos["mint0"], pos["mint1"]):
            jup = jupiter_token_info(mint)
            legs.append(
                {
                    "symbol": jup.get("symbol") if jup else None,
                    "name": jup.get("name") if jup else None,
                    "verified": None,
                    "address": mint,
                    "percent_1d": None,
                    "scam_flags": screen_solana_token(mint),
                }
            )
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


def screen_wallet_holdings(sol_simple_positions):
    """Screen every raw Solana wallet balance (not just LP legs) for scam tokens.
    This is where a spam-airdropped fake token would show up — it's not inside any
    LP position, just sitting in the wallet with a nonzero Zerion-reported value."""
    flags = []
    for p in sol_simple_positions:
        attrs = p["attributes"]
        fi = attrs.get("fungible_info") or {}
        impl = next((i for i in fi.get("implementations", []) if i.get("chain_id") == "solana"), None)
        mint = impl.get("address") if impl else None
        if not mint:
            continue
        value = attrs.get("value") or 0
        for scam_msg in screen_solana_token(mint):
            flags.append(
                {
                    "severity": "high",
                    "message": f"Wallet holding {fi.get('symbol')} ({mint}, "
                    f"${value:,.2f} [Zerion]): {scam_msg}",
                }
            )

    # Zerion's `only_simple` listing filters out tokens it treats as trash/spam — but a
    # confirmed-scam airdrop token is exactly what gets filtered that way, so check the
    # raw on-chain balances too (blocklist-only here; not worth a full Jupiter/RugCheck
    # pass on every dust token, since only the known-bad list has zero false-positive cost).
    zerion_seen_mints = set()
    for p in sol_simple_positions:
        fi = p["attributes"].get("fungible_info") or {}
        impl = next((i for i in fi.get("implementations", []) if i.get("chain_id") == "solana"), None)
        if impl and impl.get("address"):
            zerion_seen_mints.add(impl["address"])
    try:
        raw_balances = all_solana_token_balances(SOL_WALLET)
    except RuntimeError:
        raw_balances = []
    for bal in raw_balances:
        if bal["mint"] in zerion_seen_mints:
            continue  # already screened above
        if bal["mint"] in KNOWN_SCAM_ADDRESSES:
            flags.append(
                {
                    "severity": "high",
                    "message": f"Wallet holding {bal['mint']} ({bal['amount']:g} units, "
                    f"not shown by Zerion — likely filtered as spam): CONFIRMED SCAM "
                    f"({KNOWN_SCAM_ADDRESSES[bal['mint']]}) — do not hold/trade "
                    f"[Robinhood/Solana RPC direct token account scan].",
                }
            )
    return flags


def evaluate_flags(instruments):
    flags = []

    for inst in instruments:
        if inst.get("untracked_by_zerion"):
            val = f"${inst['value_usd']:,.2f}" if inst.get("value_usd") is not None else "value unknown"
            flags.append(
                {
                    "severity": "high",
                    "message": f"{inst['label']}: real on-chain position ({val}) that "
                    f"Zerion's API does not report — not included in totals from other "
                    f"tools; verify directly in the wallet/app "
                    f"[Robinhood Chain RPC direct decode].",
                }
            )

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
            for scam_msg in leg.get("scam_flags") or []:
                flags.append(
                    {
                        "severity": "high",
                        "message": f"{inst['label']} / {leg.get('address')}: {scam_msg}",
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
def build_summary(now, evm_total, evm_pnl_1d, sol_total, sol_pnl_1d, instruments, flags, trend_lines, major_prices, top_fee_pools):
    total = evm_total + sol_total
    pnl = evm_pnl_1d + sol_pnl_1d
    lines = []
    lines.append(f"DeFi Pulse — {now.strftime('%Y-%m-%d %H:%M %Z')}")
    lines.append("")
    lines.append(f"Total portfolio value: ${total:,.2f} [Zerion + Raydium/Solana RPC + GeckoTerminal]")
    lines.append(f"Today's PnL (reported, Zerion 1d changes): {pnl:+,.2f} USD")
    lines.append(f"  EVM (Robinhood chain) value: ${evm_total:,.2f} "
                  f"[Zerion + Robinhood Chain RPC direct decode for positions Zerion misses]")
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

    untracked_insts = [i for i in instruments if i.get("untracked_by_zerion")]
    if untracked_insts:
        lines.append("Positions Zerion does NOT report (found via direct RPC decode):")
        for inst in untracked_insts:
            val = f"${inst['value_usd']:,.2f}" if inst["value_usd"] is not None else "value unknown — verify manually"
            lines.append(f"  - {inst['label']}: {val} [Robinhood Chain RPC direct decode]")
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
    lines.append("")

    if top_fee_pools:
        lines.append("Top 3 fee-generating pools right now (Robinhood chain, >$1M TVL, "
                      "synthetic derivatives excluded) — Monetize score = 24h_volume x 24h_fees / TVL:")
        for p in top_fee_pools:
            score = p["volume_24h_usd"] * p["fees_24h_usd"] / p["tvl_usd"] if p["tvl_usd"] else 0
            lines.append(
                f"  - {p['name']} ({p['address']}): 24h fees ${p['fees_24h_usd']:,.2f}, "
                f"aprDay {p['apr_day']:.2f}%, score {score:,.0f} "
                f"(TVL ${p['tvl_usd']:,.0f}, 24h vol ${p['volume_24h_usd']:,.0f}) [GeckoTerminal]"
            )
        lines.append("")

    high_count = len([f for f in flags if f["severity"] == "high"])
    if high_count:
        lines.append(f"NEEDS ATTENTION TODAY: {high_count} high-risk flag(s) above.")
    else:
        lines.append("NEEDS ATTENTION TODAY: nothing high-risk flagged this check.")

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

    untracked_value_total = sum(
        i["value_usd"] or 0 for i in instruments if i.get("untracked_by_zerion")
    )
    untracked_pnl_1d = sum(
        (i["value_usd"] or 0) * (i["health"]["price_change_24h_pct"] / 100.0)
        for i in instruments
        if i.get("untracked_by_zerion") and i.get("health")
        and i["health"].get("price_change_24h_pct") is not None
    )

    sol_total = sol_wallet_total + raydium_value_total
    sol_pnl_1d = sol_wallet_pnl_1d + raydium_pnl_1d
    evm_total += untracked_value_total
    evm_pnl_1d += untracked_pnl_1d
    total = evm_total + sol_total

    flags = evaluate_flags(instruments)
    flags += screen_wallet_holdings(sol_simple)

    previous = load_previous_snapshot()
    trend_lines = compare_to_previous(total, instruments, previous)

    try:
        top_fee_pools = top_fee_pools_robinhood()
    except RuntimeError:
        top_fee_pools = []

    try:
        major_prices = coingecko_simple_price(["ethereum", "solana"])
    except RuntimeError:
        major_prices = {}

    summary = build_summary(now, evm_total, evm_pnl_1d, sol_total, sol_pnl_1d, instruments, flags, trend_lines, major_prices, top_fee_pools)
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

