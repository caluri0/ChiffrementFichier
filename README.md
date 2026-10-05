# Local File Encryption Tool / ローカルファイル暗号化ツール

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Portfolio project demonstrating **symmetric (AES)** and **asymmetric (RSA)** cryptography for protecting documents at rest. Code comments are in English to support learning and international collaboration (e.g. cybersecurity roles in Japan).

---

## English

### Why this project?

Companies in cybersecurity expect you to understand **how** encryption is used, not only which library to import. This tool implements two standard patterns:

| Mode | Algorithms | Best for |
|------|------------|----------|
| **AES (password)** | PBKDF2 + AES-256-GCM | Personal backups, single-user machines |
| **Hybrid** | RSA-OAEP + AES-256-GCM | Sharing encrypted files (public key encrypts, private key decrypts) |

**Hybrid encryption** mirrors real systems (TLS, PGP, S/MIME): RSA encrypts a small random AES key; AES encrypts the file payload.

### Security properties

- **Confidentiality**: ciphertext does not reveal plaintext without the key/password.
- **Integrity**: GCM authentication tag detects tampering (wrong password or modified file fails decryption).
- **Key stretching**: 600,000 PBKDF2 iterations slow down offline password guessing.

> **Disclaimer**: This is an educational portfolio tool, not audited production software. For real deployments, use established tools (e.g. age, GPG, OS full-disk encryption) and follow your organization's policy.

### Project structure

```
ChiffrementFichier/
├── main.py                 # CLI
├── src/
│   ├── constants.py        # File format (CFEF container)
│   ├── aes_crypto.py       # AES-GCM + PBKDF2
│   ├── rsa_crypto.py       # RSA-OAEP key wrap
│   └── file_encryptor.py   # Encrypt/decrypt files
├── requirements.txt
└── README.md
```

### Setup

```bash
cd ChiffrementFichier
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

### Usage

#### 1. Password-based AES

```bash
python main.py encrypt --mode aes -i report.pdf -o report.pdf.enc
python main.py decrypt --mode aes -i report.pdf.enc -o report.pdf
```

#### 2. RSA hybrid (generate keys once)

```bash
python main.py keygen --private keys/private.pem --public keys/public.pem
python main.py keygen --private keys/private.pem --public keys/public.pem --protect-private
```

Encrypt with **public** key; decrypt with **private** key:

```bash
python main.py encrypt --mode hybrid -i secret.docx -o secret.docx.enc --public-key keys/public.pem
python main.py decrypt --mode hybrid -i secret.docx.enc -o secret.docx --private-key keys/private.pem
```

### Learning map (read the code in this order)

1. `src/constants.py` — on-disk file format
2. `src/aes_crypto.py` — symmetric crypto building blocks
3. `src/rsa_crypto.py` — asymmetric key wrap
4. `src/file_encryptor.py` — composing both into a file workflow
5. `main.py` — user-facing CLI

### Encrypted file format (CFEF)

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 | `CFEF` |
| Version | 1 | Format version |
| Mode | 1 | `0x01` AES password, `0x02` RSA hybrid |
| Payload | … | Salt/nonce/ciphertext or wrapped key + nonce/ciphertext |

### Learning guide (PDF)

French PDF explaining all code and library choices:

```bash
python -m pip install fpdf2
python docs/generate_learning_pdf.py
```

Output: `docs/Guide_Apprentissage_Chiffrement_Fichiers.pdf`

### Roadmap (portfolio)

- [x] Learning guide PDF (French)
- [ ] Unit tests with known test vectors
- [ ] Argon2id option for password hashing
- [ ] Key rotation documentation
- [ ] Japanese UI messages (optional)
- [ ] Integration into a larger cybersecurity portfolio site

---

## 日本語

### このプロジェクトの目的

サイバーセキュリティ企業（日本含む）では、ライブラリの使い方だけでなく **暗号の仕組み** を理解していることが重要です。本ツールは次の2つの代表的な方式を実装しています。

| モード | アルゴリズム | 用途 |
|--------|--------------|------|
| **AES（パスワード）** | PBKDF2 + AES-256-GCM | 個人用バックアップ、単一PC |
| **ハイブリッド** | RSA-OAEP + AES-256-GCM | 公開鍵で暗号化し、秘密鍵で復号（ファイル共有） |

**ハイブリッド暗号**は TLS や PGP と同じ考え方です。RSA で小さな AES 鍵を包み、AES で実際のファイルを暗号化します。

### セキュリティ上の性質

- **機密性**: 鍵またはパスワードなしでは平文を得られません。
- **完全性**: GCM の認証タグにより改ざんを検出します（パスワード誤りやファイル破損も失敗します）。
- **鍵導出**: PBKDF2 を 60 万回反復し、オフラインの総当たりを遅らせます。

> **注意**: 学習・ポートフォリオ用です。本番環境では組織のポリシーに従い、実績のあるツール（age、GPG、ディスク暗号化など）を利用してください。

### セットアップ

```bash
cd ChiffrementFichier
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

### 使い方

#### 1. パスワード方式（AES）

```bash
python main.py encrypt --mode aes -i 資料.pdf -o 資料.pdf.enc
python main.py decrypt --mode aes -i 資料.pdf.enc -o 資料.pdf
```

#### 2. RSA ハイブリッド

```bash
python main.py keygen --private keys/private.pem --public keys/public.pem
python main.py encrypt --mode hybrid -i 機密.txt -o 機密.txt.enc --public-key keys/public.pem
python main.py decrypt --mode hybrid -i 機密.txt.enc -o 機密.txt --private-key keys/private.pem
```

### 学習の順番（コード閲覧）

1. `src/constants.py` — ファイル形式
2. `src/aes_crypto.py` — 対称暗号
3. `src/rsa_crypto.py` — 非対称暗号
4. `src/file_encryptor.py` — ファイル処理の統合
5. `main.py` — コマンドライン

### 学習用 PDF（フランス語）

コード全体とライブラリ選定の解説 PDF :

```bash
python docs/generate_learning_pdf.py
```

出力 : `docs/Guide_Apprentissage_Chiffrement_Fichiers.pdf`

### ポートフォリオ展望

日本のサイバーセキュリティ企業向けに、本リポジトリを起点として **脆弱性診断メモ**、**CTF write-up**、**ログ分析スクリプト** などへ拡張することを推奨します。README とコメントを英語にしているのは、国際チームや技術面接での説明に備えるためです。

---

## Author / 作者

Portfolio project — cybersecurity learning path (Japan-oriented career goal).

## License

MIT — see [LICENSE](LICENSE) if present; otherwise treat as portfolio sample code.
