# events.py
import os
import re
import json
from datetime import timezone
from dateutil import parser as dtparse

# ===== 유틸 =====
def to_utc(dt_str):
    if not dt_str:
        return None
    try:
        return dtparse.parse(dt_str).astimezone(timezone.utc).isoformat()
    except Exception:
        return None

def taglist_to_dict(taglist):
    d = {}
    if isinstance(taglist, list):
        for t in taglist:
            d[t.get("key")] = t.get("value")
    return d

def coalesce(d, *keys):
    for k in keys:
        if k in d and d[k]:
            return d[k]
    return None

def parse_reg_target(target: str):
    if not target:
        return None, None
    parts = str(target).rstrip("\\").split("\\")
    if len(parts) >= 2:
        return "\\".join(parts[:-1]), parts[-1]
    return target, None

def json_or_list(val):
    if val is None:
        return []
    s = str(val).strip()
    try:
        obj = json.loads(s)
        if isinstance(obj, list):
            return [str(x) for x in obj if x]
    except Exception:
        pass
    toks = re.split(r"[\s,;|]+", s)
    return [t for t in toks if t and t != '-']

def last_segment(path: str):
    if not path:
        return None
    s = str(path).rstrip("/\\")
    if "\\" in s:
        return s.split("\\")[-1] or s
    return os.path.basename(s) or s

# ===== 스키마 제약(DDL) =====
DDL = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Trace) REQUIRE t.traceID IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.key IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (f:File) REQUIRE f.path IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (i:Ip) REQUIRE i.addr IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (rk:RegistryKey) REQUIRE rk.path IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (rv:RegistryValue) REQUIRE rv.path IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (pipe:Pipe) REQUIRE pipe.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (wf:WmiFilter) REQUIRE wf.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (wc:WmiConsumer) REQUIRE wc.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (dv:Device) REQUIRE dv.path IS UNIQUE",
]

# ===== Cypher 모음 =====
CYPHER = {
    "trace": """
    MERGE (t:Trace {traceID:$traceID})
    """,

    "process": """
    MERGE (p:Process {key:$key})
    ON CREATE SET
      p.image       = $image,
      p.CommandLine = $CommandLine
    ON MATCH SET
      p.ProcessGuid       = coalesce($ProcessGuid, p.ProcessGuid),
      p.ParentProcessGuid = coalesce($ParentProcessGuid, p.ParentProcessGuid),
      p.image             = coalesce($image, p.image),
      p.CommandLine       = coalesce($CommandLine, p.CommandLine)
    WITH p
    MATCH (t:Trace {traceID:$traceID})
    MERGE (t)-[:HAS_PROCESS]->(p)
    """,

    "spawn": """
    MATCH (parent:Process {key:$pkey})
    MATCH (child:Process {key:$ckey})
    MERGE (parent)-[:SPAWNS]->(child)
    """,

    "file": """MERGE (f:File {path:$path})""",
    "file_edge": """
      MATCH (p:Process {key:$pkey})
      MATCH (f:File {path:$path})
      MERGE (p)-[r:CREATED_FILE]->(f)
      SET r.event_id=$event_id
    """,

    "dns_ip": """MERGE (i:Ip {addr:$addr})""",
    "net_ip_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (i:Ip {addr:$addr})
    MERGE (p)-[r:CONNECTED_TO]->(i)
    SET r.event_id=$event_id, r.proto=$proto, r.dport=$dport
    """,

    "reg_key": """MERGE (rk:RegistryKey {path:$path})""",
    "reg_value": """
    MERGE (rv:RegistryValue {path:$path})
    SET rv.valueName = $valueName
    """,
    "reg_under": """
    MATCH (rv:RegistryValue {path:$vpath})
    MATCH (rk:RegistryKey {path:$kpath})
    MERGE (rv)-[:UNDER_KEY]->(rk)
    """,
    "proc_sets_reg": """
      MATCH (p:Process {key:$pkey})
      MATCH (rv:RegistryValue {path:$vpath})
      MERGE (p)-[r:SET_REG_VALUE]->(rv)
      SET r.event_id=$event_id, r.valueName=$valueName
    """,

    "pipe": """MERGE (pipe:Pipe {name:$name})""",
    "pipe_created_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (pipe:Pipe {name:$name})
    MERGE (p)-[r:CREATED_PIPE]->(pipe)
    SET r.event_id=$event_id
    """,
    "pipe_connected_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (pipe:Pipe {name:$name})
    MERGE (p)-[r:CONNECTED_PIPE]->(pipe)
    SET r.event_id=$event_id
    """,

    "wmi_filter": """
    MERGE (wf:WmiFilter {name:$name})
    SET wf.query = coalesce($query, wf.query)
    """,
    "wmi_consumer": """
    MERGE (wc:WmiConsumer {name:$name})
    SET wc.command = coalesce($command, wc.command)
    """,
    "wmi_bind": """
    MATCH (wf:WmiFilter {name:$filter})
    MATCH (wc:WmiConsumer {name:$consumer})
    MERGE (wf)-[r:BIND_TO]->(wc)
    SET r.event_id=$event_id
    """,

    "deleted_file_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:DELETED_FILE]->(f)
    SET r.event_id=$event_id
    """,

    "process_tamper_edge": """
    MATCH (a:Process {key:$src_key})
    MATCH (b:Process {key:$dst_key})
    MERGE (a)-[r:TAMPERED]->(b)
    SET r.event_id=$event_id, r.details=coalesce($details, r.details)
    """,

    "created_executable_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:CREATED_EXECUTABLE]->(f)
    SET r.event_id=$event_id, r.mode=$mode
    """,

    "file_time_changed_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:MODIFIED_FILE_TIME]->(f)
    SET r.event_id=$event_id, r.what=$what
    """,

    "loaded_module_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:LOADED_MODULE]->(f)
    SET r.event_id=$event_id
    """,
    "loaded_driver_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:LOADED_DRIVER]->(f)
    SET r.event_id=$event_id
    """,

    "device": """MERGE (dv:Device {path:$path})""",
    "raw_read_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (dv:Device {path:$path})
    MERGE (p)-[r:RAW_READ]->(dv)
    SET r.event_id=$event_id
    """,

    "created_reg_key": """
    MATCH (p:Process {key:$pkey})
    MATCH (rk:RegistryKey {path:$kpath})
    MERGE (p)-[r:CREATED_REG_KEY]->(rk)
    SET r.event_id=$event_id
    """,
    "deleted_reg_key": """
    MATCH (p:Process {key:$pkey})
    MATCH (rk:RegistryKey {path:$kpath})
    MERGE (p)-[r:DELETED_REG_KEY]->(rk)
    SET r.event_id=$event_id
    """,
    "renamed_reg_key": """
    MATCH (p:Process {key:$pkey})
    MATCH (old:RegistryKey {path:$old_path})
    MATCH (new:RegistryKey {path:$new_path})
    MERGE (p)-[r:RENAMED_REG_KEY]->(new)
    SET r.event_id=$event_id
    MERGE (old)-[:RENAMED_TO]->(new)
    """,
    "renamed_reg_value": """
    MATCH (p:Process {key:$pkey})
    MATCH (old:RegistryValue {path:$old_path})
    MATCH (new:RegistryValue {path:$new_path})
    MERGE (p)-[r:RENAMED_REG_VALUE]->(new)
    SET r.event_id=$event_id
    MERGE (old)-[:RENAMED_TO]->(new)
    """,
    "file_stream_edge": """
    MATCH (p:Process {key:$pkey})
    MATCH (f:File {path:$path})
    MERGE (p)-[r:CREATED_STREAM]->(f)
    SET r.event_id=$event_id, r.stream=$stream, r.hash=$hash
    """,
    "inject_thread_edge": """
    MATCH (a:Process {key:$src_key})
    MATCH (b:Process {key:$dst_key})
    MERGE (a)-[r:INJECTED_THREAD]->(b)
    SET r.event_id=$event_id
    """,
    "process_access_edge": """
    MATCH (a:Process {key:$src_key})
    MATCH (b:Process {key:$dst_key})
    MERGE (a)-[r:ACCESSED_PROCESS]->(b)
    SET r.event_id=$event_id, r.grantedAccess=$grantedAccess
    """,
}

def ensure_schema(driver):
    with driver.session() as s:
        for stmt in DDL:
            s.run(stmt)

# ===== 이벤트 라우터 + 핸들러 =====
def handle_span(sess, trace_id, span):
    span_id = span.get("spanID") or span.get("id")
    tags = taglist_to_dict(span.get("tags", []))

    if "EventID" in tags and isinstance(tags["EventID"], str):
        try:
            tags["EventID"] = int(tags["EventID"])
        except Exception:
            pass

    ev_id = coalesce(tags, "EventID", "ID")
    guid  = coalesce(tags, "ProcessGuid", "process_guid", "ProcessGUID")
    pguid = coalesce(tags, "ParentProcessGuid", "parent_process_guid", "ParentProcessGUID")

    pid  = coalesce(tags, "ProcessId","process_id","pid","Pid","processId")
    ppid = coalesce(tags, "ParentProcessId","parent_pid","ParentPid","ppid","parentPid","sysmon.ppid")
    img_raw = coalesce(tags, "Image","process_path","ImagePath","image","PathToImage")
    image = os.path.basename(str(img_raw or ""))
    cmd = coalesce(tags, "CommandLine", "command_line")

    # 8/10/25 계열은 Source* 기준으로 보정
    if str(ev_id) in {"8", "10", "25"}:
        if not guid:
            guid = coalesce(tags, "SourceProcessGuid", "SourceProcessGUID", "source_process_guid")
        if not pid:
            pid = coalesce(tags, "SourceProcessId", "source_process_id")
        if not img_raw:
            img_raw = coalesce(tags, "SourceImage")
        image = os.path.basename(str(img_raw or ""))

    # pkey(GUID 우선, 없으면 traceID:pid)
    pkey = guid if guid else (f"{trace_id}:{pid}" if pid else None)

    # Process 노드 생성/연결
    if pkey:
        sess.run(
            CYPHER["process"],
            key=pkey,
            traceID=trace_id,
            ProcessGuid=guid,
            ParentProcessGuid=pguid,
            image=image,
            CommandLine=cmd,
        )
        parent_key = None
        if pguid:
            parent_key = pguid
            sess.run(CYPHER["process"], key=parent_key, traceID=trace_id,
                     ProcessGuid=pguid, ParentProcessGuid=None, image=None, CommandLine=None)
        elif ppid:
            parent_key = f"{trace_id}:{ppid}"
            sess.run(CYPHER["process"], key=parent_key, traceID=trace_id,
                     ProcessGuid=None, ParentProcessGuid=None, image=None, CommandLine=None)
        if parent_key:
            sess.run(CYPHER["spawn"], pkey=parent_key, ckey=pkey)

    # ===== 이벤트별 처리 =====
    # 2: File creation time changed
    if str(ev_id) == "2" and pkey:
        target = coalesce(tags, "TargetFilename", "Path")
        if target:
            sess.run(CYPHER["file"], path=target)
            sess.run(CYPHER["file_time_changed_edge"], pkey=pkey, path=target, event_id=ev_id, what="CreationTime")

    # 3: NetworkConnect
    if str(ev_id) == "3" and pkey:
        dip = coalesce(tags, "DestinationIp", "dst_ip")
        dport = coalesce(tags, "DestinationPort", "dst_port")
        proto = coalesce(tags, "Protocol")
        dhost = coalesce(tags, "DestinationHostname")
        if dip:
            sess.run(CYPHER["dns_ip"], addr=dip)
            sess.run(CYPHER["net_ip_edge"], pkey=pkey, addr=dip, event_id=ev_id, proto=proto, dport=dport)
        if dhost:
            dhost_l = str(dhost).lower()
            sess.run(CYPHER["dns_ip"], addr=dhost_l)
            sess.run(CYPHER["net_ip_edge"], pkey=pkey, addr=dhost_l, event_id=ev_id, proto=proto, dport=dport)

    # 6: Driver Loaded
    if str(ev_id) == "6" and pkey:
        img = coalesce(tags, "ImageLoaded", "Image")
        if img:
            sess.run(CYPHER["file"], path=img)
            sess.run(CYPHER["loaded_driver_edge"], pkey=pkey, path=img, event_id=ev_id)

    # 7: Image/DLL Loaded
    if str(ev_id) == "7" and pkey:
        img = coalesce(tags, "ImageLoaded", "Image")
        if img:
            sess.run(CYPHER["file"], path=img)
            sess.run(CYPHER["loaded_module_edge"], pkey=pkey, path=img, event_id=ev_id)

    # 8: CreateRemoteThread
    if str(ev_id) == "8":
        dst_pid = coalesce(tags, "TargetProcessId", "TargetPid")
        dst_guid = coalesce(tags, "TargetProcessGuid", "TargetProcessGUID", "target_process_guid")
        if pkey and (dst_guid or dst_pid):
            dst_key = dst_guid if dst_guid else (f"{trace_id}:{dst_pid}" if dst_pid else None)
            if dst_key:
                sess.run(CYPHER["process"], key=dst_key, traceID=trace_id,
                         ProcessGuid=dst_guid, ParentProcessGuid=None, image=None, CommandLine=None)
                sess.run(CYPHER["inject_thread_edge"], src_key=pkey, dst_key=dst_key, event_id=ev_id)

    # 9: RawAccessRead (device access)
    if str(ev_id) == "9" and pkey:
        device = coalesce(tags, "Device")
        if device:
            sess.run(CYPHER["device"], path=device)
            sess.run(CYPHER["raw_read_edge"], pkey=pkey, path=device, event_id=ev_id)

    # 10: ProcessAccess
    if str(ev_id) == "10":
        granted = coalesce(tags, "GrantedAccess")
        dst_pid = coalesce(tags, "TargetProcessId", "TargetPid")
        dst_guid = coalesce(tags, "TargetProcessGuid", "TargetProcessGUID", "target_process_guid")
        if pkey and (dst_guid or dst_pid):
            dst_key = dst_guid if dst_guid else (f"{trace_id}:{dst_pid}" if dst_pid else None)
            if dst_key:
                sess.run(CYPHER["process"], key=dst_key, traceID=trace_id,
                         ProcessGuid=dst_guid, ParentProcessGuid=None, image=None, CommandLine=None)
                sess.run(CYPHER["process_access_edge"], src_key=pkey, dst_key=dst_key,
                         event_id=ev_id, grantedAccess=granted)

    # 11: FileCreate
    if str(ev_id) == "11":
        target = coalesce(tags, "TargetFilename", "Path")
        if target and pkey:
            sess.run(CYPHER["file"], path=target)
            sess.run(CYPHER["file_edge"], pkey=pkey, path=target, event_id=ev_id)

    # 12: Registry Key Create/Delete
    if str(ev_id) == "12" and pkey:
        etype = coalesce(tags, "EventType")
        kpath = coalesce(tags, "TargetObject")
        if kpath:
            sess.run(CYPHER["reg_key"], path=kpath)
            lower = str(etype).lower() if etype else ""
            if lower.startswith("create"):
                sess.run(CYPHER["created_reg_key"], pkey=pkey, kpath=kpath, event_id=ev_id)
            elif lower.startswith("delete"):
                sess.run(CYPHER["deleted_reg_key"], pkey=pkey, kpath=kpath, event_id=ev_id)

    # 13: RegistryValueSet
    if str(ev_id) == "13":
        target = coalesce(tags, "TargetObject")
        if target and pkey:
            key_path, value_name = parse_reg_target(target)
            vpath = target
            if key_path:
                sess.run(CYPHER["reg_key"], path=key_path)
            sess.run(CYPHER["reg_value"], path=vpath, valueName=value_name)
            if key_path:
                sess.run(CYPHER["reg_under"], vpath=vpath, kpath=key_path)
            sess.run(CYPHER["proc_sets_reg"], pkey=pkey, vpath=vpath, event_id=ev_id, valueName=value_name)

    # 14: Registry Rename
    if str(ev_id) == "14" and pkey:
        old = coalesce(tags, "TargetObject")
        new = coalesce(tags, "NewName", "NewDetails")
        if old and new:
            sess.run(CYPHER["reg_key"], path=old)
            sess.run(CYPHER["reg_key"], path=new)
            sess.run(CYPHER["renamed_reg_key"], pkey=pkey, old_path=old, new_path=new, event_id=ev_id)

    # 15: FileCreateStreamHash
    if str(ev_id) == "15" and pkey:
        target = coalesce(tags, "TargetFilename", "Path")
        stream = coalesce(tags, "StreamName", "Stream")
        hashv = coalesce(tags, "Hash", "Hashes")
        if target:
            sess.run(CYPHER["file"], path=target)
            sess.run(CYPHER["file_stream_edge"], pkey=pkey, path=target, event_id=ev_id, stream=stream, hash=hashv)

    # 17: Pipe Created
    if str(ev_id) == "17" and pkey:
        pname = coalesce(tags, "PipeName", "Pipe")
        if pname:
            sess.run(CYPHER["pipe"], name=pname)
            sess.run(CYPHER["pipe_created_edge"], pkey=pkey, name=pname, event_id=ev_id)

    # 18: Pipe Connected
    if str(ev_id) == "18" and pkey:
        pname = coalesce(tags, "PipeName", "Pipe")
        if pname:
            sess.run(CYPHER["pipe"], name=pname)
            sess.run(CYPHER["pipe_connected_edge"], pkey=pkey, name=pname, event_id=ev_id)

    # 19: WMI EventFilter
    if str(ev_id) == "19" and pkey:
        fname = coalesce(tags, "FilterName", "Name", "EventFilterName")
        fquery = coalesce(tags, "Query", "QueryName")
        if fname:
            sess.run(CYPHER["wmi_filter"], name=fname, query=fquery)

    # 20: WMI EventConsumer
    if str(ev_id) == "20" and pkey:
        cname = coalesce(tags, "ConsumerName", "Name", "Consumer")
        ccmd = coalesce(tags, "CommandLine", "Command")
        if cname:
            sess.run(CYPHER["wmi_consumer"], name=cname, command=ccmd)

    # 21: WMI FilterToConsumer binding
    if str(ev_id) == "21" and pkey:
        filter_name = coalesce(tags, "FilterName", "Filter")
        consumer_name = coalesce(tags, "ConsumerName", "Consumer")
        if filter_name and consumer_name:
            sess.run(CYPHER["wmi_bind"], filter=filter_name, consumer=consumer_name, event_id=ev_id)

    # 23 / 26: File Delete
    if str(ev_id) in ["23", "26"] and pkey:
        t = coalesce(tags, "TargetFilename", "Path")
        if t:
            sess.run(CYPHER["file"], path=t)
            sess.run(CYPHER["deleted_file_edge"], pkey=pkey, path=t, event_id=ev_id)

    # 25: Process Tampering
    if str(ev_id) == "25":
        details = coalesce(tags, "Details", "Info")
        dst_pid = coalesce(tags, "TargetProcessId", "TargetPid")
        dst_guid = coalesce(tags, "TargetProcessGuid", "TargetProcessGUID", "target_process_guid")
        if pkey and (dst_guid or dst_pid):
            dst_key = dst_guid if dst_guid else (f"{trace_id}:{dst_pid}" if dst_pid else None)
            if dst_key:
                sess.run(CYPHER["process"], key=dst_key, traceID=trace_id,
                         ProcessGuid=dst_guid, ParentProcessGuid=None, image=None, CommandLine=None)
                sess.run(CYPHER["process_tamper_edge"], src_key=pkey, dst_key=dst_key, event_id=ev_id, details=details)

    # 27: File Block Executable
    if str(ev_id) == "27" and pkey:
        target = coalesce(tags, "TargetFilename", "Path")
        if target:
            sess.run(CYPHER["file"], path=target)
            sess.run(CYPHER["created_executable_edge"], pkey=pkey, path=target, event_id=ev_id, mode="blocked")

    # 29: File Executable Detected
    if str(ev_id) == "29" and pkey:
        target = coalesce(tags, "TargetFilename", "Path")
        if target:
            sess.run(CYPHER["file"], path=target)
            sess.run(CYPHER["created_executable_edge"], pkey=pkey, path=target, event_id=ev_id, mode="detected")


def load_trace_file(sess, path):
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    trace_id = data.get("traceID") or f"FILE::{os.path.basename(path)}"
    sess.run(CYPHER["trace"], traceID=trace_id)
    spans = data.get("spans", [])
    try:
        spans = sorted(spans, key=lambda x: x.get("startTime", 0))
    except Exception:
        pass
    for sp in spans:
        handle_span(sess, trace_id, sp)
    print(f"[+] Loaded {len(spans)} spans from {os.path.basename(path)}")
