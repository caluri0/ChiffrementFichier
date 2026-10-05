#!/usr/bin/env python3
"""
CLI entry point for the local file encryption tool.

Examples:
  # Password mode (AES-256-GCM + PBKDF2)
  python main.py encrypt --mode aes -i document.pdf -o document.pdf.enc
  python main.py decrypt --mode aes -i document.pdf.enc -o document.pdf

  # Hybrid mode (RSA wraps AES key)
  python main.py keygen --private keys/private.pem --public keys/public.pem
  python main.py encrypt --mode hybrid -i secret.txt -o secret.txt.enc --public-key keys/public.pem
  python main.py decrypt --mode hybrid -i secret.txt.enc -o secret.txt --private-key keys/private.pem
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from src import file_encryptor, rsa_crypto


def _prompt_password(confirm: bool = False) -> str:
    pwd = getpass.getpass("Password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if pwd != again:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not pwd:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return pwd


def cmd_keygen(args: argparse.Namespace) -> None:
    private_path = Path(args.private)
    public_path = Path(args.public)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    pem_password: str | None = None
    if args.protect_private:
        pem_password = _prompt_password(confirm=True)

    private_key, public_key = rsa_crypto.generate_rsa_keypair()
    rsa_crypto.save_private_key_pem(private_key, private_path, pem_password)
    rsa_crypto.save_public_key_pem(public_key, public_path)
    print(f"RSA key pair written to:\n  {private_path}\n  {public_path}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.mode == "aes":
        password = args.password or _prompt_password()
        file_encryptor.encrypt_file_aes_password(input_path, output_path, password)
    elif args.mode == "hybrid":
        if not args.public_key:
            print("--public-key is required for hybrid mode.", file=sys.stderr)
            sys.exit(1)
        file_encryptor.encrypt_file_rsa_hybrid(
            input_path, output_path, Path(args.public_key)
        )
    else:
        print(f"Unknown mode: {args.mode}", file=sys.stderr)
        sys.exit(1)

    print(f"Encrypted: {output_path}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.mode == "aes":
            password = args.password or _prompt_password()
            file_encryptor.decrypt_file_aes_password(
                input_path, output_path, password
            )
        elif args.mode == "hybrid":
            if not args.private_key:
                print("--private-key is required for hybrid mode.", file=sys.stderr)
                sys.exit(1)
            pem_password = args.pem_password
            if pem_password is None and args.private_key_protected:
                pem_password = getpass.getpass("PEM password: ") or None
            file_encryptor.decrypt_file_rsa_hybrid(
                input_path,
                output_path,
                Path(args.private_key),
                pem_password,
            )
        else:
            print(f"Unknown mode: {args.mode}", file=sys.stderr)
            sys.exit(1)
    except (file_encryptor.FileFormatError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted: {output_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local file encryption (AES-GCM, RSA hybrid) — portfolio learning tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate RSA public/private PEM keys")
    keygen.add_argument("--private", required=True, help="Output path for private PEM")
    keygen.add_argument("--public", required=True, help="Output path for public PEM")
    keygen.add_argument(
        "--protect-private",
        action="store_true",
        help="Encrypt private PEM with a password",
    )
    keygen.set_defaults(func=cmd_keygen)

    for name in ("encrypt", "decrypt"):
        cmd = sub.add_parser(name, help=f"{name.capitalize()} a file")
        cmd.add_argument(
            "--mode",
            choices=("aes", "hybrid"),
            required=True,
            help="aes = password + AES-GCM; hybrid = RSA + AES",
        )
        cmd.add_argument("-i", "--input", required=True, help="Input file path")
        cmd.add_argument("-o", "--output", required=True, help="Output file path")
        cmd.add_argument(
            "--password",
            help="Password for aes mode (prompted if omitted)",
        )
        cmd.add_argument("--public-key", help="Public PEM for hybrid encrypt")
        cmd.add_argument("--private-key", help="Private PEM for hybrid decrypt")
        cmd.add_argument(
            "--pem-password",
            help="Password if private PEM is encrypted (hybrid decrypt)",
        )
        cmd.add_argument(
            "--private-key-protected",
            action="store_true",
            help="Prompt for PEM password on hybrid decrypt",
        )
        cmd.set_defaults(func=cmd_encrypt if name == "encrypt" else cmd_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
