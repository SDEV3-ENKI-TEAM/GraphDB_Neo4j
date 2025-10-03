# main.py
import os
from neo4j import GraphDatabase, basic_auth

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASS, INPUT_FILES
from events import ensure_schema, load_trace_file

def main():
    if not INPUT_FILES:
        print("INPUT_FILES에 JSON 경로를 넣으세요")
        return

    driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASS))
    with driver.session() as sess:
        ensure_schema(driver)
        for p in INPUT_FILES:
            load_trace_file(sess, p)
    driver.close()
    print("완료. http://localhost:7474 에서 확인하세요.")


if __name__ == "__main__":
    main()
