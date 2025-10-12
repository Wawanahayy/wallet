# wallet

# generate-keys.mjs (append-only, safe)
# Flags:
## --count=N               : jumlah akun per mnemonic (default 5)
### --mnemonic-count=M      : jumlah mnemonic yang dibuat (default 1)
### --only-mnemonic         : hanya tulis mnemonic (tidak tulis private keys)
### --only-private          : hanya tulis private keys (mnemonic dibuat internal, TIDAK ditulis)
### --out-mnemonic=PATH     : path file mnemonic (default ./generate/mnemonic.txt)
### --out-private=PATH      : path file private keys (default ./generate/privatekeys.txt)

# Catatan:
### - SELALU append. Tidak pernah menghapus isi file lama.
### - Jika folder tujuan belum ada, akan dibuat otomatis.
 
pharse
```
node generate.mjs --mnemonic-count=50
```

1 pharse and 50 privatekey

```
node generate.mjs
```
