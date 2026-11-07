"""Version02 evidence; preserve the original 96-test artifacts byte-for-byte."""
import importlib.util
from pathlib import Path


OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("nonhttp_v1_verifier", OUT.parent / "verify_contract.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
verifier.OUT = OUT


if __name__ == "__main__":
    verifier.main()
