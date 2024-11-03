import json


def containsIt(s):
    # related process ids to malicious program
    return True
    ids = {144797, 144798, 144799, 144802, 144803, 144805, 144806, 144808, 144809, 144811, 144812, 144814, 144815, 144817, 144818, 144820, 144821, 144832, 144834, 144837, 144838, 144840, 144841, 144843, 144844, 144846, 144847, 144848, 144849, 144850, 144851, 144852, 144853, 144854, 144855, 144856, 144857, 144858, 144859, 144860, 144861, 144863, 144864, 144865, 144867, 144868, 144869, 144870, 144871, 144873, 144875}
    for id in ids:
        if str(id) in s:
            return True
    return False


def main():
    processMap = {}
    syscallMap = {}
    malicious_id = "process19886"
    malicious_related = [malicious_id]
    delcarations = []
    syscallDependencies = []
    processInfo = []
    parentProcesses = []
    with open('auditbeat_output1.ndjson') as f:
        malicious_count = 0
        for line in f:
            event = json.loads(line)

            # Extract data
            process = event.get('process', {})
            user = event.get('user', {})
            # if user.get("id") != "1000":
            #     continue
            # event_details = event.get('event', {})
            if process.get("name") is None:
                continue
            if not containsIt(line):
                continue
            # if "program" in process.get('name'):
            #     malicious_count += 1
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
            # if process.get("name") == "modinfo":
            #     continue
            # if process.get("name") == "ld-linux-x86-64":
            #     continue
            # if process.get('parent') and process.get('parent').get("pid") != 0:
            #     if process.get('parent').get("pid") == 142179:
            #         continue

            if pid not in processMap:
                # print(process_cypher)
                processInfo.append(process_cypher)
                processMap[pid] = syscall + "_" + str(abs(hash(path)))

            if len(syscall) > 0 and len(path) > 0 and str(hash(syscall)) + str(hash(path)) not in syscallMap:
                syscall_object = f"""MERGE (SYS{pid}_{syscall}_{str(abs(hash(path)))}:Process {{pid: '{pid}', name: '{path}'}})"""
                syscall_dependency = f"""MERGE ({pid})-[:{syscall}]->(SYS{pid}_{syscall}_{str(abs(hash(path)))})"""
                # print(syscall_object)
                # print(syscall_dependency)
                delcarations.append(syscall_object)
                syscallDependencies.append(syscall_dependency)
                syscallMap[str(hash(syscall)) + str(hash(path))] = True

            if process.get('parent') and process.get('parent').get("pid") != 0:
                parent_id = "process" + str(process.get('parent').get("pid"))
                parent_process_cypher = f"""MERGE ({parent_id})-[:PARENT_OF]->({pid})"""
                if pid in malicious_id:
                    malicious_related.append(parent_id)
                # print(parent_process_cypher)
                parentProcesses.append(parent_process_cypher)

    with open('new_output1.txt', "w") as outputFile:
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
