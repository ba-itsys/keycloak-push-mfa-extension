#!/usr/bin/env python3
import base64
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def usage() -> None:
    print("usage: sign_jws.py <alg> <key-file> <signing-input>", file=sys.stderr)


def require_algorithm(name: str) -> str:
    mapping = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
        "ES256": hashes.SHA256(),
        "ES384": hashes.SHA384(),
        "ES512": hashes.SHA512(),
    }
    upper = name.upper()
    if upper not in mapping:
        raise SystemExit(f"unsupported signing algorithm: {name}")
    return upper, mapping[upper]


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> None:
    if len(sys.argv) != 4:
        usage()
        raise SystemExit(1)

    alg, hash_alg = require_algorithm(sys.argv[1])
    key_path = sys.argv[2]
    signing_input = sys.argv[3].encode("ascii")

    with open(key_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)

    if alg.startswith("RS"):
        signature = key.sign(signing_input, padding.PKCS1v15(), hash_alg)
    elif alg.startswith("ES"):
        der_sig = key.sign(signing_input, ec.ECDSA(hash_alg))
        r, s = decode_dss_signature(der_sig)
        coordinate_size = (key.key_size + 7) // 8
        signature = r.to_bytes(coordinate_size, "big") + s.to_bytes(coordinate_size, "big")
    else:
        raise SystemExit(f"unsupported algorithm family: {alg}")

    print(base64url(signature))


if __name__ == "__main__":
    main()
