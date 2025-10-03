# config.py
import os
import glob
from dotenv import load_dotenv

load_dotenv()

# ===== 접속/경로 설정 =====
NEO4J_URI  = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")

INPUT_DIR   = os.getenv("INPUT_DIR")  # JSON 파일 폴더
INPUT_FILES = []
if INPUT_DIR and os.path.isdir(INPUT_DIR):
    INPUT_FILES = sorted(glob.glob(os.path.join(INPUT_DIR, "*.json")))
