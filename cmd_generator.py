import json

def findProcessAccessSecret():
    with open('auditbeat_output.ndjson') as newf:
        for line in newf:
            if "secret.txt" in line:
                event = json.loads(line)
                process = event.get('process', {})
                pid = "process" + str(process.get('pid'))
                newf.close()
                return pid
    newf.close()
    return None


def main():
    processMap = {}
    syscallMap = {}
    delcarations = []
    malicious_id = findProcessAccessSecret()
    malicious_related = [malicious_id]
    syscallDependencies = []
    processInfo = []
    parentProcesses = []
    with open('auditbeat_output.ndjson') as f:
        malicious_count = 0
        for line in f:
            event = json.loads(line)

            # Extract data
            process = event.get('process', {})
            if process.get("name") is None:
                continue
            pid = "process" + str(process.get('pid'))
            syscall = ""
            path = ""
            if "program" in process.get('name') and malicious_count != 1:
                if "auditd" in event:
                    auditd = event.get("auditd")
                    if "data" in auditd:
                        data = auditd.get("data")
                        if "syscall" in data:
                            syscall = data.get('syscall')
                    if "paths" in auditd:
                        paths = auditd.get("paths")
                        if "name" in paths[0]:
                            path = paths[0].get("name")

            process_cypher = f"""MERGE ({pid}:Process {{pid: '{pid}', name: '{process.get('name')}'}})"""
            if process.get("name") == "modinfo":
                continue
            if process.get("name") == "ld-linux-x86-64":
                continue

            if pid not in processMap:
                processInfo.append(process_cypher)
                processMap[pid] = syscall + "_" + str(abs(hash(path)))

            if len(syscall) > 0 and len(path) > 0 and str(hash(syscall)) + str(hash(path)) not in syscallMap:
                syscall_object = f"""MERGE (SYS{pid}_{syscall}_{str(abs(hash(path)))}:Process {{pid: '{pid}', name: '{path}'}})"""
                syscall_dependency = f"""MERGE ({pid})-[:{syscall}]->(SYS{pid}_{syscall}_{str(abs(hash(path)))})"""
                delcarations.append(syscall_object)
                syscallDependencies.append(syscall_dependency)
                syscallMap[str(hash(syscall)) + str(hash(path))] = True

            if process.get('parent') and process.get('parent').get("pid") != 0:
                parent_id = "process" + str(process.get('parent').get("pid"))
                parent_process_cypher = f"""MERGE ({parent_id})-[:PARENT_OF]->({pid})"""
                if pid in malicious_id:
                    malicious_related.append(parent_id)
                parentProcesses.append(parent_process_cypher)

    with open('neo4j_cmds.txt', "w") as outputFile:
        for s in set(processInfo):
            for malicious in malicious_related:
                if malicious in s:
                    s = s.replace("Process", "MaliciousProcess")
                    break
            outputFile.write(s + "\n")
        for s in set(delcarations):
            for malicious in malicious_related:
                if malicious in s:
                    s = s.replace("Process", "MaliciousProcess")
                    break
            outputFile.write(s + "\n")
        for s in set(parentProcesses):
            outputFile.write(s + "\n")
        for s in set(syscallDependencies):
            outputFile.write(s + "\n")


if __name__ == "__main__":
    main()
