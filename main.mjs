#!/usr/bin/env node
/**
 * generate-keys.mjs — parallel wallet scan + BLAST_MODE + UNTIL_FOUND + address logger + Telegram notify
 *
 * - Prioritas scan: hanya MAINNET dari whitelist (lihat ALLOWED_MAINNET_CHAINIDS).
 * - TESTNET: hanya Sepolia (11155111).
 * - Hanya simpan mnemonic/PK **jika ada saldo** (native>0 atau token raw>0).
 * - Kirim Telegram (jika TELEGRAM_NOTIFY=1) saat ada saldo → address, privateKey, chainId.
 * - Per chain: kumpulkan SEMUA token positif (dari semua indexer di INDEXER_ORDER).
 *
 * Deps:
 *   npm i dotenv undici p-limit viem ethers
 */

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pLimit from 'p-limit';
import { request as undiciRequest } from 'undici';
import { ethers } from 'ethers';
import { createPublicClient, http } from 'viem';

/* ---------------- optional indexer hub ---------------- */
let indexerHub = null;
try {
  const mod = await import('./indexer-helpers.mjs'); // opsional
  if (mod && typeof mod.makeIndexer === 'function') {
    indexerHub = mod.makeIndexer({ VERBOSE: !!Number(process.env.VERBOSE ?? 0) });
  }
} catch { /* ignore */ }

/* ---------------- Moralis key rotator ---------------- */
class SimpleKeyPool {
  constructor(keys = [], opts = {}) {
    this.keys = (keys || []).map(s => s.trim()).filter(Boolean);
    this.cooldownMs = Number(opts.cooldownMs ?? 60_000);
    this.maxAttempts = Math.max(2, Number(opts.maxAttempts ?? this.keys.length * 2));
    this.cooling = new Map();
    this._i = 0;
  }
  _now(){ return Date.now(); }
  _isCooling(k){ const u=this.cooling.get(k); if(!u) return false; if(this._now()>=u){ this.cooling.delete(k); return false; } return true; }
  _cd(k,extra=0){ this.cooling.set(k, this._now()+this.cooldownMs+extra); }
  async nextKey() {
    if (!this.keys.length) throw new Error('No MORALIS_API_KEYS provided');
    for (let j=0;j<this.keys.length;j++) {
      const k=this.keys[(this._i+j)%this.keys.length];
      if (!this._isCooling(k)) { this._i=(this._i+j+1)%this.keys.length; return k; }
    }
    const soonest = Math.min(...[...this.cooling.values()]);
    const wait = Math.max(0, soonest - this._now());
    await new Promise(r=>setTimeout(r, wait));
    return this.nextKey();
  }
  async withKey(fn) {
    let last;
    for (let a=0; a<this.maxAttempts; a++) {
      const key = await this.nextKey();
      try {
        const res = await fn(key);
        const s = res?.status ?? res?.statusCode ?? 0;
        if (s>=200 && s<300) return res;
        if ([401,402,403,429].includes(s)) this._cd(key, 3000+Math.random()*1000);
        else this._cd(key, 1000+Math.random()*500);
        last = new Error(`HTTP ${s || 'ERR'}`);
      } catch(e) {
        this._cd(key, 1500+Math.random()*500);
        last = e;
      }
    }
    throw last ?? new Error('moralis exhausted');
  }
}

/* ---------------- CLI & ENV ---------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const argv = new Map(process.argv.slice(2).map(s => {
  const m = s.match(/^--([^=]+)(=(.*))?$/); return m ? [m[1], m[3] ?? '1'] : [s, '1'];
}));

const ARG_MNEMONIC_COUNT = Math.max(1, Number(argv.get('mnemonic-count') ?? 100));
const BATCH_SIZE         = Math.max(1, Number(argv.get('batch-size') ?? 10));

const ENV_PER_MNEMONIC   = Number(process.env.PER_MNEMONIC ?? '');
const PER_MNEMONIC       = Math.max(1, Number(isNaN(ENV_PER_MNEMONIC) ? (argv.get('per-mnemonic') ?? 2) : ENV_PER_MNEMONIC)); // default 2
const SAVE_PK_COUNT      = Math.max(1, Number(process.env.SAVE_PK_COUNT ?? PER_MNEMONIC));

const ONLY_MNEMONIC  = argv.has('only-mnemonic');
const ONLY_PRIVATE   = argv.has('only-private');

const CHAIN_LIMIT    = Math.max(1, Number(process.env.CHAIN_LIMIT ?? 400));
const ADDR_CONCURRENCY  = Math.max(1, Number(process.env.ADDR_CONCURRENCY ?? 8));
const CHAIN_CONCURRENCY = Math.max(1, Number(process.env.CHAIN_CONCURRENCY ?? 12));
const RPC_CONCURRENCY   = Math.max(1, Number(process.env.RPC_CONCURRENCY ?? 4));

const SCAN_DELAY_MS  = Math.max(0, Number(process.env.SCAN_DELAY_MS ?? 0));
const PROGRESS_WIDTH = Math.max(10, Number(process.env.PROGRESS_WIDTH ?? 60));
const HEARTBEAT_MS   = Math.max(500, Number(process.env.HEARTBEAT_MS ?? 1200));
const VERBOSE        = !!Number(process.env.VERBOSE ?? 0);

const RPC_TIMEOUT_MS        = Math.max(1000, Number(process.env.RPC_TIMEOUT_MS ?? 6000));
const RPC_RETRY             = Math.max(0, Number(process.env.RPC_RETRY ?? 0));
const MORALIS_TIMEOUT_MS    = Math.max(1000, Number(process.env.MORALIS_TIMEOUT_MS ?? 6000));
const CHAIN_HARD_TIMEOUT_MS = Math.max(2000, Number(process.env.CHAIN_HARD_TIMEOUT_MS ?? 9000));

const OUT_MNEMONIC = path.resolve(process.env.OUT_MNEMONIC || path.resolve(__dirname, 'mnemonic.txt'));
const OUT_PRIVATE  = path.resolve(process.env.OUT_PRIVATE  || path.resolve(__dirname, 'privatekey.txt'));
const OUT_ADDRESS  = path.resolve(process.env.OUT_ADDRESS  || path.resolve(__dirname, 'address.txt'));
const DERIVATION_PREFIX = `m/44'/60'/0'/0/`;

const MORALIS_KEYS = (process.env.MORALIS_API_KEYS || '').split(',').map(s=>s.trim()).filter(Boolean);
const moralisPool  = MORALIS_KEYS.length ? new SimpleKeyPool(MORALIS_KEYS, { cooldownMs: Number(process.env.MORALIS_COOLDOWN_MS || 60_000) }) : null;

const INDEXER_ORDER = (process.env.INDEXER_ORDER || 'moralis,covalent,ankr,simplehash,alchemy,quicknode,zapper,zerion,bitquery,blockchair')
  .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

const BLAST_MODE   = !!Number(process.env.BLAST_MODE || 0);
const UNTIL_FOUND  = argv.has('until-found') || !!Number(process.env.CONTINUE_UNTIL_FOUND || 0);
const TARGET_FOUND = Math.max(1, Number(argv.get('target-found') ?? (UNTIL_FOUND ? 1 : 0))); // jika until-found, default 1

/* ---------------- Telegram notify ---------------- */
const TG_ENABLED  = !!Number(process.env.TELEGRAM_NOTIFY || 0);
const TG_TOKEN    = process.env.TELEGRAM_BOT_TOKEN || '';
const TG_CHAT_ID  = process.env.TELEGRAM_CHAT_ID || '';
const TG_THREAD   = process.env.TELEGRAM_THREAD_ID || '';
const REDACT_PK   = !!Number(process.env.REDACT_PK || 0);

function redactPk(pk){
  if (!pk) return '';
  if (!REDACT_PK) return pk;
  return pk.length > 12 ? (pk.slice(0, 8) + '…' + pk.slice(-6)) : pk;
}
function escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
async function sendTelegram(text){
  if (!TG_ENABLED) return;
  if (!TG_TOKEN || !TG_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${TG_TOKEN}/sendMessage`;
  const body = {
    chat_id: TG_CHAT_ID,
    text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };
  if (TG_THREAD) body.message_thread_id = Number(TG_THREAD);

  for (let i=0;i<3;i++){
    try{
      const r = await undiciRequest(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        bodyTimeout: 8000,
        headersTimeout: 8000,
      });
      if (r.statusCode >= 200 && r.statusCode < 300) return;
    }catch{}
    await new Promise(r=>setTimeout(r, 1000*(i+1)));
  }
}

/* ---------------- Progress (anti-crash + extend) ---------------- */
class Rate {
  constructor(){ this.prevT=Date.now(); this.prevDone=0; this.rate=0; }
  sample(done){
    const t=Date.now(), dt=(t-this.prevT)/1000;
    if(dt>=0.5){
      this.rate=(done-this.prevDone)/Math.max(dt,0.001);
      this.prevT=t; this.prevDone=done;
    }
  }
  eta(total,done){
    if(this.rate<=0) return 'ETA: --:--';
    const left=Math.max(0,total-done);
    const s=Math.ceil(left/Math.max(this.rate,0.001));
    const m=Math.floor(s/60);
    return `ETA: ${String(m).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
  }
}
class Progress {
  constructor(totalUnits, width=60){
    this.total = Math.max(1,totalUnits);
    this.done = 0; this.found = 0; this.req = 0; this.err = 0;
    this.width = Math.max(1,width);
    this.providers = {}; this.active = 0; this.rate = new Rate();
  }
  extend(n){ if (n>0) this.total += n; }
  unit(){
    const pct = Math.floor((this.done/Math.max(1,this.total))*100);
    return Math.min(100, Math.max(0, pct));
  }
  bar(){
    const ratio = Math.min(1, Math.max(0, this.done / Math.max(1,this.total)));
    const filled = Math.min(this.width, Math.max(0, Math.floor(this.width * ratio)));
    const empty  = Math.max(0, this.width - filled);
    return '█'.repeat(filled)+'░'.repeat(empty);
  }
  tickDone(n=1){ this.done+=n; this.rate.sample(this.done); }
  tickReq(n=1){ this.req+=n; }
  tickErr(n=1){ this.err+=n; }
  tickFound(n=1){ this.found+=n; }
  use(name){ this.providers[name]=(this.providers[name]||0)+1; }
  draw(){
    const prov=Object.entries(this.providers).map(([k,v])=>`${k}:${v}`).join(' ');
    const eta=this.rate.eta(this.total,this.done);
    const rps=this.rate.rate.toFixed(1);
    process.stdout.write('\r'+`[${this.bar()}] ${String(this.unit()).padStart(3,' ')}% · units ${this.done}/${this.total} · ~${rps}/s · ${eta} · found ${this.found} · req ${this.req} · err ${this.err} · active ${this.active}${prov?' · '+prov:''}`);
  }
  finish(){ this.draw(); process.stdout.write('\n'); }
}

/* ---------------- Utils ---------------- */
function appendFileSyncEnsure(filePath, content) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, content, { encoding: 'utf8', flag: 'a' });
}
function ensureCsvHeader(filePath, headers){
  const exists = fs.existsSync(filePath);
  const size = exists ? fs.statSync(filePath).size : 0;
  if (!exists || size === 0){
    const line = headers.join(',') + '\n';
    appendFileSyncEnsure(filePath, line);
  }
}
function writeCsvRow(filePath, headers, obj){
  ensureCsvHeader(filePath, headers);
  const row = headers.map(h => {
    let v = obj[h];
    if (v === undefined || v === null) v = '';
    v = String(v);
    if (v.includes('"') || v.includes(',') || v.includes('\n')) {
      v = '"' + v.replace(/"/g, '""') + '"';
    }
    return v;
  }).join(',') + '\n';
  appendFileSyncEnsure(filePath, row);
}
function shortHost(u){
  try { const { hostname } = new URL(u); return hostname; } catch { return ''; }
}
function parseBigInt(v){
  if (typeof v === 'string' && v.startsWith('0x')) { try { return BigInt(v); } catch { return 0n; } }
  try { return BigInt(v); } catch { return 0n; }
}
function abortable(fetcher, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetcher(ctrl.signal).finally(() => clearTimeout(t));
}
function hasPositiveTokens(tokens){
  if (!Array.isArray(tokens)) return false;
  for (const t of tokens){
    try { if (BigInt(t?.raw ?? 0) > 0n) return true; } catch {}
  }
  return false;
}

/* ---------------- Chains (whitelist mainnets + Sepolia testnet only) ---------------- */
const REGISTRY_URL = 'https://chainid.network/chains.json';
const BAD_PATTERNS = ['${','wss://','multichain'];

// Whitelist of mainnet chainIds to scan
const ALLOWED_MAINNET_CHAINIDS = new Set([
  1,      // Ethereum Mainnet
  8453,   // Base
  42161,  // Arbitrum One
  42170,  // Arbitrum Nova (include Nova)
  10,     // Optimism
  137,    // Polygon
  56,     // BNB Chain
  324,    // zkSync Era
  59144,  // Linea
  43114,  // Avalanche
  250,    // Fantom
  100,    // Gnosis (xDai)
  1284,   // Moonbeam
  66,     // OKXChain
  5000,   // example placeholder (remove if undesired)
  10_000  // placeholder
]);

// Allowed testnet ids (only Sepolia)
const ALLOWED_TESTNET_CHAINIDS = new Set([
  11155111 // Sepolia
]);

async function fetchJson(u){
  const r = await undiciRequest(u,{method:'GET'});
  if (r.statusCode < 200 || r.statusCode >= 300) throw new Error('HTTP '+r.statusCode);
  return r.body.json();
}
function norm(x){
  return {
    chainId: Number(x.chainId ?? -1),
    name: x.name || `chain-${x.chainId}`,
    testnet: !!x.testnet,
    rpcs: (x.rpc || []).filter(Boolean).map(s => String(s).replace(/\/$/,'')),
    symbol: x.nativeCurrency?.symbol || 'ETH',
    decimals: Number(x.nativeCurrency?.decimals ?? 18),
  };
}
function pickRpcs(rpcs){
  const out=[];
  for(const u of rpcs){
    if(!u || !u.startsWith('https://')) continue;
    if(BAD_PATTERNS.some(p=>u.includes(p))) continue;
    out.push(u);
  }
  return out;
}

// allowChain uses whitelist of mainnet chainIds; testnet only Sepolia
function allowChain(c){
  if (!c) return false;
  if (c.testnet) {
    // Allow Sepolia only
    return ALLOWED_TESTNET_CHAINIDS.has(Number(c.chainId));
  }
  // mainnet: allow if chainId in whitelist
  if (ALLOWED_MAINNET_CHAINIDS.has(Number(c.chainId))) return true;

  // Fallback: allow by checking name keywords (in case chainId unknown)
  const name = (c.name || '').toLowerCase();
  const okKeywords = ['ethereum','base','arbitrum','optimism','polygon','matic','bnb','bsc','zk','zksync','linea','avalanche','fantom','gnos','moonbeam','okx','mantle'];
  for (const kw of okKeywords) if (name.includes(kw)) return true;

  return false;
}

async function loadChains(limit = 400){
  const raw = await fetchJson(REGISTRY_URL);
  const arr = raw.map(norm).filter(c => c.chainId > 0 && allowChain(c));
  for (const c of arr) c.rpcs = pickRpcs(c.rpcs);
  const usable = arr.filter(c => c.rpcs.length > 0);
  usable.sort((a,b) => {
    // keep order stable; prefer well-known chains by chainId presence
    const aRank = ALLOWED_MAINNET_CHAINIDS.has(a.chainId) ? 0 : 1;
    const bRank = ALLOWED_MAINNET_CHAINIDS.has(b.chainId) ? 0 : 1;
    if (aRank !== bRank) return aRank - bRank;
    return a.chainId - b.chainId;
  });
  const sliced = usable.slice(0, limit);
  const mainCount = sliced.filter(c => !c.testnet).length;
  const sepoliaCount = sliced.filter(c => c.chainId === 11155111).length;
  console.log(`[chains] mainnet=${mainCount} sepolia=${sepoliaCount} total=${sliced.length}`);
  return sliced;
}

/* ---------------- Moralis for INDEXER_ORDER=moralis (reused) ---------------- */
async function moralisTokens(chainId, address){
  const keysOk = !!moralisPool;
  if (!keysOk) return { ok:false, any:false, via:'moralis', nonfatal:true };
  const toHex = n => '0x' + Number(n).toString(16);
  const base = (process.env.MORALIS_BASE || 'https://deep-index.moralis.io/api/v2.2').replace(/\/$/,'');
  const url  = `${base}/wallets/${address}/tokens?chain=${encodeURIComponent(toHex(chainId))}`;
  try{
    const res = await moralisPool.withKey(key =>
      abortable((signal)=> undiciRequest(url, {
        method:'GET', headers:{ 'x-api-key': key },
        bodyTimeout: MORALIS_TIMEOUT_MS, headersTimeout: MORALIS_TIMEOUT_MS, signal
      }), MORALIS_TIMEOUT_MS)
    );
    const status = res.statusCode ?? res.status;
    if (status === 400 || status === 404) return { ok:true, any:false, tokens:[], via:'moralis' };
    const json = await res.body.json().catch(()=> ({}));
    const items = json?.result || json?.items || [];
    const tokens = [];
    for (const it of items) {
      const bal = parseBigInt(it.balance ?? it.token_balance ?? it.raw_balance ?? it.amount ?? 0);
      if (bal===0n) continue;
      tokens.push({ token: (it.contract_address || it.token_address || null) || null, symbol: it.contract_ticker_symbol ?? it.symbol ?? 'TKN', raw: bal.toString() });
    }
    return { ok:true, any: tokens.length>0, tokens, via:'moralis' };
  } catch(e) {
    return { ok:false, any:false, via:'moralis', nonfatal:true, reason:String(e?.message||e) };
  }
}

/* ---------------- New: aggregate tokens from all providers (dedupe) ---------------- */
async function tokensAllByOrder(chainId, address){
  const order = (process.env.INDEXER_ORDER || 'moralis,covalent,ankr,simplehash,alchemy,quicknode,zapper,zerion,bitquery,blockchair')
    .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

  const map = new Map(); // tokenAddr -> { token, symbol, raw: BigInt }
  const addTokens = (arr) => {
    if (!Array.isArray(arr)) return;
    for (const t of arr){
      const tokAddr = String(t?.token ?? '').toLowerCase() || '';
      const symbol = t?.symbol ?? t?.contract_ticker_symbol ?? 'TKN';
      let raw;
      try { raw = BigInt(t.raw ?? t.amount ?? t.balance ?? '0'); } catch { raw = 0n; }
      if (raw <= 0n) continue;
      if (!tokAddr){
        const key = `__noaddr__:${symbol}:${t.raw || t.amount || ''}:${Math.random().toString(36).slice(2,8)}`;
        map.set(key, { token: null, symbol, raw });
      } else {
        if (!map.has(tokAddr)) map.set(tokAddr, { token: tokAddr, symbol, raw });
        else {
          try { map.get(tokAddr).raw += raw; } catch { /* ignore */ }
        }
      }
    }
  };

  for (const name of order){
    if (name === 'moralis'){
      const r = await moralisTokens(chainId, address);
      if (r.ok && r.any) addTokens(r.tokens || []);
      if (!r.ok && r.nonfatal) continue;
    } else {
      if (!indexerHub || typeof indexerHub.tryProvider !== 'function') continue;
      try{
        const r = await indexerHub.tryProvider(name, chainId, address);
        if (r?.skip) continue;
        if (r?.ok && r?.any) addTokens(r.tokens || []);
        if (!r?.ok && r?.nonfatal) continue;
      }catch{ /* ignore provider errors */ }
    }
  }

  const arr = Array.from(map.values()).map(x => ({ token: x.token, symbol: x.symbol, raw: x.raw.toString() }));
  return { ok:true, any: arr.length>0, tokens: arr, via: order.join(',') || 'none' };
}

/* ---------------- Native (all RPC parallel per chain) ---------------- */
async function nativeAnyParallel(address, chain, rpcPool){
  let found = null;
  await Promise.allSettled(chain.rpcs.map(rpc => rpcPool(async () => {
    try {
      const client = createPublicClient({
        chain: { id: chain.chainId },
        transport: http(rpc, { batch: true, timeout: RPC_TIMEOUT_MS, retryCount: RPC_RETRY }),
      });
      const res = await abortable(sig => client.getBalance({ address, signal: sig }), RPC_TIMEOUT_MS);
      if (!found && res > 0n) found = { ok:true, any:true, wei: res.toString(), symbol: chain.symbol, rpc };
    } catch { /* ignore this rpc */ }
  })));
  return found || { ok:true, any:false };
}

/* ---------------- Scan address (parallel throttled) — collect ALL hits per chain ---------------- */
async function scanAddressParallel(addr, CHAINS, bar, chainPool, rpcPool){
  const allHits = [];
  await Promise.allSettled(
    CHAINS.map(chain => chainPool(async () => {
      const result = await Promise.race([
        (async () => {
          const nat = await nativeAnyParallel(addr, chain, rpcPool);
          bar.tickReq();
          const tkAll = await tokensAllByOrder(chain.chainId, addr);
          bar.tickReq();

          const okNative = nat?.any;
          const okToken  = tkAll?.any && hasPositiveTokens(tkAll.tokens);

          if (okNative || okToken){
            allHits.push({
              chain,
              native: okNative ? nat : null,
              tokens: okToken ? tkAll.tokens : [],
              via: (okToken ? tkAll.via : (okNative ? 'native' : 'none')),
            });
            bar.tickFound();
          }
        })(),
        new Promise(r => setTimeout(() => r({ timeout: true }), CHAIN_HARD_TIMEOUT_MS))
      ]).catch(() => null);

      bar.tickDone(1);
    }))
  );
  return allHits;
}

/* ---------------- Scan address (BLAST) — no chain throttling ---------------- */
async function scanAddressBlast(addr, CHAINS, bar, rpcPool){
  const allHits = [];
  await Promise.allSettled(
    CHAINS.map(chain => (async () => {
      const result = await Promise.race([
        (async () => {
          const nat = await nativeAnyParallel(addr, chain, rpcPool);
          bar.tickReq();
          const tkAll = await tokensAllByOrder(chain.chainId, addr);
          bar.tickReq();

          const okNative = nat?.any;
          const okToken  = tkAll?.any && hasPositiveTokens(tkAll.tokens);

          if (okNative || okToken){
            allHits.push({
              chain,
              native: okNative ? nat : null,
              tokens: okToken ? tkAll.tokens : [],
              via: (okToken ? tkAll.via : (okNative ? 'native' : 'none')),
            });
            bar.tickFound();
          }
        })(),
        new Promise(r => setTimeout(() => r({ timeout: true }), CHAIN_HARD_TIMEOUT_MS))
      ]).catch(() => null);

      bar.tickDone(1);
    })())
  );
  return allHits;
}

/* ---------------- MAIN ---------------- */
(async ()=>{
  try{
    const MNEMONIC_COUNT = UNTIL_FOUND ? Number.POSITIVE_INFINITY : ARG_MNEMONIC_COUNT;

    console.log(`Config: (max) mnemonics=${UNTIL_FOUND ? '∞ (until-found)' : MNEMONIC_COUNT} batch=${BATCH_SIZE} per_mnemonic=${PER_MNEMONIC} target_found=${TARGET_FOUND}`);
    console.log(`SAVE_PK_COUNT=${SAVE_PK_COUNT}  BLAST_MODE=${BLAST_MODE ? 'ON' : 'OFF'}  UNTIL_FOUND=${UNTIL_FOUND ? 'ON' : 'OFF'}`);
    console.log('INDEXER_ORDER:', (process.env.INDEXER_ORDER || '').split(',').map(s=>s.trim()).filter(Boolean).join(' → ') || '(default)');
    if (TG_ENABLED) console.log('Telegram notify: ON');
    if (!MORALIS_KEYS.length && !indexerHub) {
      console.log('WARN: Tanpa MORALIS_API_KEYS & tanpa indexer-helpers → hanya native via RPC.');
    }

    const CHAINS = await loadChains(CHAIN_LIMIT);
    const totalUnitsStatic = (isFinite(MNEMONIC_COUNT) ? MNEMONIC_COUNT : ARG_MNEMONIC_COUNT) * PER_MNEMONIC * CHAINS.length;
    const bar = new Progress(totalUnitsStatic || CHAINS.length, PROGRESS_WIDTH);
    bar.draw();

    const heartbeat = setInterval(()=>{ bar.draw(); process.stdout.write(`\n[hb] active=${bar.active} req=${bar.req} found=${bar.found} err=${bar.err}\n`); }, HEARTBEAT_MS);

    const addrPool  = pLimit(ADDR_CONCURRENCY);
    const chainPool = pLimit(CHAIN_CONCURRENCY);
    const rpcPool   = pLimit(RPC_CONCURRENCY);

    const CSV_HEADERS = ['ts','address','index','chain_id','chain_name','via','native_wei','symbol','rpc_host','tokens_count','tokens_json'];
    ensureCsvHeader(OUT_ADDRESS, CSV_HEADERS);

    let processedMnemonics = 0, foundMnemonics = 0;

    async function processBatch(nBatch){
      const phrases = Array.from({length: nBatch}, () => ethers.Mnemonic.fromEntropy(ethers.randomBytes(32)).phrase);

      const res = await Promise.all(phrases.map(phrase => addrPool(async () => {
        const derived = [];
        for (let j=0;j<PER_MNEMONIC;j++){
          const w = ethers.HDNodeWallet.fromPhrase(phrase, undefined, `${DERIVATION_PREFIX}${j}`);
          derived.push({ index: j, address: w.address, privateKey: w.privateKey });
        }

        let foundThisMnemonic = false;

        const perAddrResults = await Promise.all(derived.map(d => (async ()=>{
          if (SCAN_DELAY_MS) await new Promise(r=>setTimeout(r, SCAN_DELAY_MS));
          bar.active++;
          try {
            const hits = BLAST_MODE
              ? await scanAddressBlast(d.address, CHAINS, bar, rpcPool)
              : await scanAddressParallel(d.address, CHAINS, bar, chainPool, rpcPool);

            if (hits && hits.length){
              for (const hit of hits){
                const okNative = !!(hit.native?.any && BigInt(hit.native?.wei ?? '0') > 0n);
                const okToken  = Array.isArray(hit.tokens) && hit.tokens.length > 0;
                if (!okNative && !okToken) continue;

                const tokens_json = okToken ? JSON.stringify(hit.tokens) : '';

                writeCsvRow(OUT_ADDRESS, CSV_HEADERS, {
                  ts: new Date().toISOString(),
                  address: d.address,
                  index: d.index,
                  chain_id: hit.chain.chainId,
                  chain_name: hit.chain.name,
                  via: hit.via || (okNative ? 'native' : 'indexer'),
                  native_wei: okNative ? (hit.native?.wei ?? '') : '',
                  symbol: okNative ? (hit.native?.symbol ?? '') : '',
                  rpc_host: okNative ? shortHost(hit.native?.rpc || '') : '',
                  tokens_count: okToken ? (hit.tokens?.length ?? 0) : 0,
                  tokens_json,
                });

                if (TG_ENABLED){
                  const pkForAddr = derived.find(x => x.index === d.index)?.privateKey || '';
                  const txt =
                    `<b>WALLET FOUND</b>\n` +
                    `address: <code>${escHtml(d.address)}</code>\n` +
                    `privateKey: <code>${escHtml(redactPk(pkForAddr))}</code>\n` +
                    `chainId: <b>${hit.chain.chainId}</b>  (${escHtml(hit.chain.name)})\n` +
                    `via: ${escHtml(hit.via || (okNative ? 'native' : 'indexer'))}\n` +
                    (okNative ? `native: ${hit.native.wei} wei (${hit.native.symbol})\n` : ``) +
                    (okToken ? `tokens: ${hit.tokens.length}\n` : ``) +
                    (okNative && hit.native.rpc ? `rpc: ${escHtml(shortHost(hit.native.rpc))}\n` : ``) +
                    (okToken ? `\nTokens sample:\n${escHtml(JSON.stringify((hit.tokens||[]).slice(0,6)))}\n` : '');
                  await sendTelegram(txt);
                }

                if (!ONLY_PRIVATE) appendFileSyncEnsure(OUT_MNEMONIC, phrase + '\n');
                if (!ONLY_MNEMONIC) {
                  const toSave = derived.slice(0, SAVE_PK_COUNT).map(x => x.privateKey);
                  if (toSave.length) appendFileSyncEnsure(OUT_PRIVATE, toSave.join('\n')+'\n');
                }

                process.stdout.write(`\n[FOUND] addr[${d.index}] ${d.address} on ${hit.chain.name} (#${hit.chain.chainId}) via ${hit.via || (okNative ? 'native' : 'indexer')}\n`);
                if (okNative) console.log(`        native: ${hit.native.wei} wei (${hit.native.symbol}) [rpc=${hit.native.rpc || '-'}]`);
                if (okToken){
                  console.log(`        tokens: ${hit.tokens.length}`);
                  for (const t of (hit.tokens || []).slice(0,8)) console.log(`          - ${t.symbol} raw=${t.raw} token=${t.token}`);
                  if ((hit.tokens||[]).length>8) console.log(`          (+${hit.tokens.length-8} more)`);
                }

                foundThisMnemonic = true;
              }
              return true;
            }
            return false;
          } finally { bar.active--; }
        })()))

        if (perAddrResults.some(Boolean)) foundThisMnemonic = true;

        if (!foundThisMnemonic) console.log(`[nohit] mnemonic skipped (no balance on ${PER_MNEMONIC} addr)`);
        return !!foundThisMnemonic;
      })));

      processedMnemonics += nBatch;
      for (const ok of res) if (ok) foundMnemonics++;
      process.stdout.write(`\n[batch] done → processed_mnemonics=${processedMnemonics}${isFinite(MNEMONIC_COUNT)?'/'+MNEMONIC_COUNT:''} · found=${foundMnemonics}\n`);
    }

    while ((processedMnemonics < MNEMONIC_COUNT) && (!UNTIL_FOUND ? (TARGET_FOUND===0 || foundMnemonics < TARGET_FOUND)
                                                                  : (foundMnemonics < TARGET_FOUND))) {
      const n = Math.min(BATCH_SIZE, isFinite(MNEMONIC_COUNT) ? (MNEMONIC_COUNT - processedMnemonics) : BATCH_SIZE);

      // Tambah total unit sesuai batch baru → progress % akurat & tidak overflow
      // units per batch = n * PER_MNEMONIC * CHAINS.length
      bar.extend(n * PER_MNEMONIC * CHAINS.length);

      await processBatch(n);
      if (UNTIL_FOUND && foundMnemonics >= TARGET_FOUND) break;
    }

    clearInterval(heartbeat);
    bar.finish();
    console.log(`✅ Selesai. Found mnemonics: ${foundMnemonics}${UNTIL_FOUND ? ' (until-found mode)' : `/${processedMnemonics}`}. Output:`);
    if (!ONLY_PRIVATE) console.log('  -', OUT_MNEMONIC);
    if (!ONLY_MNEMONIC) console.log('  -', OUT_PRIVATE);
    console.log('  -', OUT_ADDRESS);
  }catch(e){
    console.error('\nFatal:', e?.message ?? e);
    process.exit(1);
  }
})();
