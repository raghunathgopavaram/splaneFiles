import getopt
import sys
import os
import time
import datetime
import subprocess
import signal
import re
import tarfile
import glob
import decimal
import ipaddress
import multiprocessing
# Global parameters
INTERFACE = "sriov0"
PCAP_MAX_SIZE_MB = 2
RMS_THRESHOLD = 5000
COUNT_MAX = 1000
PCAP_ROTATED_COUNT = 2
TIME_SLOT_INTVL = 60
timeSlotText = "2m ago"
timeSlotTextMax = "10m ago"
MAX_SIZE_MB = 2000000  # 2MB logs rotation
MAX_ROTATED_FILES = 1  # for logs rotation
instanceNo = 0
CWD = os.getcwd()
serviceName="Pmc"
processes_started=[]
servicesStarted=[]
processes_in_multiprocess=[]
# Files used
tempLog = "temp.log"
scriptLog = "script.log"
cpuStatsLog = "cpuStat.log"
ptp4lTempLog = "ptp4lTemp.log"
phc2sysTempLog = "phc2sysTemp.log"
current_time = datetime.datetime.now().strftime("%Y-%m-%d_T_%H-%M-%S")
pcapLog = 'splane-{}.pcap'.format(current_time)
timingMgrLog = "timingmgr.log"
logrotateConfig = "logrotate.conf"
ptp4lLog = "ptp4l.log"
phc2sysLog = "phc2sys.log"
pmcTsFile = "pmcLog"
T1_to_T4_tsOut = "t1t2t3t4.csv"
ptp4lCli= "/etc/sysconfig/ptp4l"
pmcSystemdService="/usr/lib/systemd/system/Pmc.service"
timingMgrLogTemp="timingmgrTemp.log"
pmcCmdScriptFile="pmc.sh"
waitCmdScriptFile="wait.sh"
AnalyseOutFile="Analysis.log"
AnalyseFileTemp="AnalysisTemp.log"

# function to write the logs
def echo_write(msg):
    with open(scriptLog, 'a') as f:
        f.write('{}-{}: {}\n'.format(datetime.datetime.now().strftime("%Y-%m-%d_T_%H:%M:%S"), instanceNo, msg))

def echo_clear(msg):
    with open(scriptLog, 'w') as f:
        f.write('{}-{}: {}\n'.format(datetime.datetime.now().strftime("%Y-%m-%d_T_%H:%M:%S"), instanceNo, msg))

def help():

    echo_write("""
----------------------------- ABOUT THE SCRIPT ------------------------------------------

This script is to detect timing issue (jump) and automatically  collect splane pcaps, cpustats, logs.

---------------------------------------------------------------
To start the script in the background for splane and cpu stats
---------------------------------------------------------------
nohup ./<script_name> -i <interface_name to capture pcap> -s <max size allowed for pcap in MB> &>> script.log &

-------------------------------------------
To run the script for t1t2t3t4 timestamps
------------------------------------------
./<scriptname> -p collectTs -S <size for rotated logs>   [to collect Timestamps]

Note: Ctrl + C to stop the script
Note: Can't run the script in background for collecting timestamps

------------------------
To check the script logs
------------------------
tail -f <directory of the script>/script.log

----------------------------
To checkout the help section
-----------------------------
./<script_name> -h  --> to see the help section

Note: root access is needed to run the script
Note: Use Ctrl+Z to stop the script if needed
Note: please wait for this log ---> done collecting the logs .. please send us ptp4l_jump_issue.tar.gz file to check

---------------------------------- END --------------------------------------------------
""")

#function to check if the registered client ip of timingmgr are pingable
def isPingable(ip, podname): # rerurn
    ip_obj = ipaddress.ip_address(ip)  #check the version of ip address ipv4 or ipv6
    if ip_obj.version == 4:
        pingCommand = 'ping'
    elif ip_obj.version == 6:
        pingCommand = 'ping6'
    command = f"kubectl exec -i {podname} -- {pingCommand} -c 1 -W 1 {ip}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return_status = process.returncode
    if return_status == 0:
        return True
    else:
        echo_write("ping failed for DU IP {} with stdOut:\n {}".format(ip,process.stdout))
        return False

def writeTimingMgrClientsPingStatus(): #returns true if all the clients are pingable
    #call this function once unified-timingmgr is pingable
    #extract the client ip from the unified-timingmgr
    podname = findtimingPod()
    if podname == None:
        echo_write("could not find the unified-timingmgr pod to get the clientsData")
        return False
    command = f"kubectl exec {podname} -- cat /var/log/clientData.json"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status_logs = process.returncode
    if status_logs == 0 and len(process.stdout) > 2: #min len possible is 2 ([])
        clientDataOut = process.stdout
    else:
        echo_write(f"No client data found from unified-timingmgr: {process.stdout}")
        return False
    #parse the client data once found
    #sample output --> [{"url": "http://[fd74:ca9b:3a09:868c:172:18:0:7d04]:8080/DU/", "appID": 2, "msID": 3, "basebandID": 1}, {"url": "http://[fd74:ca9b:3a09:868c:172:18:0:7d04]:8080/DU/", "appID": 2, "msID": 3, "basebandID": 1}]
    pattern1 = r'\[([a-fA-F\d.:]+)\]' #for ipv6 addressses
    pattern2 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' #for ipv4 addressses
    # Extract the IP address using the pattern
    ipv6 = re.findall(pattern1, clientDataOut)
    ipv4 = re.findall(pattern2, clientDataOut)
    ips = ipv4 + ipv6
    #check if the extracted ips are pingable
    for ip in ips:
        if isPingable(ip,podname):
            pass
        else:
            return False
    return True
def startPingTestInLoop():
    while True:
        writeTimingMgrClientsPingStatus()
        time.sleep(5)                  #sleep for 5 sec
    exit_program()

def startDUPingTest():
    process = multiprocessing.Process(target=startPingTestInLoop)
    process.start()
    processes_in_multiprocess.append(process)


#starts the pmc and returns the popen object which can be used to kill 
def startPmcAsSystemd():
    pmcCmd=f'''#!/bin/bash
{CWD}/{waitCmdScriptFile} | /usr/sbin/pmc -u -i /tmp/foo >> {CWD}/{pmcTsFile}'''
    waitCmd=f'''#!/bin/bash
echo "hii"
while true; do
    sleep 1
done'''
    with open(pmcCmdScriptFile,'w') as f:
        f.write(pmcCmd)
    os.chmod(pmcCmdScriptFile, 0o777)
    with open(waitCmdScriptFile,'w') as f:
        f.write(waitCmd)
    os.chmod(waitCmdScriptFile, 0o777)
    serviceFile=f'''[Unit]
Description=Service to collect Timestamps for splane
After=network.target

[Service]
User=root
ExecStart={CWD}/pmc.sh

[Install]
WantedBy=multi-user.target'''
    with open(pmcSystemdService,'w') as f:
        f.write(serviceFile)
    command = "systemctl daemon-reload"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    command = f"systemctl enable {serviceName}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    command = f"systemctl start {serviceName}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    servicesStarted.append(serviceName)
def is_service_running(service_name):
    cmd = f"systemctl status {service_name}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        output_str = output.decode('utf-8')
        if "Active: active (running)" in output_str:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        return False

def startPmc():
    with open(pmcTsFile, 'a') as f:
        # Run the command and redirect its output to the file
        proc = subprocess.Popen(['echo','"raghu"','|','/usr/sbin/pmc', '-u', '-i', '/tmp/foo'], stdout=f,stderr=f)
        processes_started.append(proc)
        echo_write('started pmc with pid {}'.format(proc.pid))
    return proc   #can access pid as proc.pid, or send signal as proc.send_signal()
def startTcpDump():
    #tcpdump -q -i $INTERFACE -W $PCAP_ROTATED_COUNT -C $PCAP_MAX_SIZE_MB ether proto 0x88f7 -w $pcapLog >/dev/null 2>&1 &
    with open('/dev/null', 'w') as devnull:
        proc = subprocess.Popen(['tcpdump', '-q','-i', INTERFACE,'-W',str(PCAP_ROTATED_COUNT), '-C', str(PCAP_MAX_SIZE_MB),'ether', 'proto','0x88f7', '-w',pcapLog], stdout=devnull, stderr=devnull)
        echo_write('started tcpdump with pid {}'.format(proc.pid))
        processes_started.append(proc)
    return proc
def startSarOut():
    #sar -u 1 -P $PTP4L_CORES >> $cpuStatsLog &
    cores = findPtp4lCores()
    with open(cpuStatsLog, 'a') as f:
        proc = subprocess.Popen(['sar','-u','1','-P', cores],stderr=f,stdout=f)
        processes_started.append(proc)
        echo_write('started sar with pid {}'.format(proc.pid))
    return proc
def findPtp4lCores():
    pid_ptp4l = subprocess.check_output(['pidof', 'ptp4l']).decode('utf-8').strip()
    pid_phc2sys = subprocess.check_output(['pidof', 'phc2sys']).decode('utf-8').strip()
    echo_write(f"pid of ptp4l: {pid_ptp4l} and pid of phc2sys: {pid_phc2sys}")
    ptp4l_cores = subprocess.check_output(['taskset', '-c', '-p', pid_ptp4l]).decode('utf-8').split(':')[1].strip()
    echo_write(f"found core affinity of ptp4l --> {ptp4l_cores}")
    return ptp4l_cores
def createPreStopTar():
    timeNow = datetime.datetime.now().strftime("%Y-%m-%d_T_%H-%M-%S")
    tarFileName = "preStopLogs-{}.tar.gz".format(timeNow)
    #tar all the files if available as prestop logs 
    files_to_archive = [ptp4lLog, phc2sysLog, logrotateConfig, timingMgrLog, phc2sysTempLog,
                    ptp4lTempLog, scriptLog, pcapLog, cpuStatsLog,timingMgrLogTemp,pmcCmdScriptFile,waitCmdScriptFile,pmcTsFile]    
    rotatedFiles=[glob.glob(pcapLog+"[012]"), glob.glob(cpuStatsLog+"-*"),glob.glob(scriptLog+"-*"),glob.glob(pmcTsFile+"-*")]
    with tarfile.open(tarFileName, "w:gz") as tar:
        for file in files_to_archive:
            try:
                tar.add(file)
            except FileNotFoundError:
                pass
        for file in rotatedFiles:
            for rot_file in file:
                try:
                    tar.add(rot_file)
                except FileNotFoundError:
                    pass
    for files in rotatedFiles:
        clearLogs(files)
    clearLogs(files_to_archive)
def reRun_service(serv):
    command = "systemctl daemon-reload"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    command = f"systemctl enable {serv}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    command = f"systemctl start {serv}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    command = f"systemctl restart {serv}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    echo_write("rerun service {} done".format(serv))
def cleanup():
    for proc in processes_started:
        proc.send_signal(signal.SIGTERM)
        echo_write('cleared subprocess{}.'.format(proc.pid))
    for service in servicesStarted:
        stopService(service)
        if service==serviceName:
            #recover the timestamps if servie is Pmc
            recoverTS()
    for process in processes_in_multiprocess:
        if process.is_alive():
            process.terminate()
            process.join()
    createPreStopTar()
def stopService(service):
    command = f"systemctl stop {service}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    echo_write("stopping service {} done".format(service))

def isPidRunning(pid):
    if os.path.exists('/proc/{}/status'.format(pid)):
        try:
            status = os.waitpid(pid, os.WNOHANG)[1]
            if status == os.WIFSTOPPED(0):
                echo_write(f"Process with PID {pid} has become a zombie")
                return False
            else:
                return True
        except ChildProcessError:
            echo_write(f"Process with PID {pid} has exited")
            return False
    else:
        echo_write('PID {} is not running.'.format(pid))
        return False

def configurePtp4lCmdl(ptp4l_config):
    with open(ptp4lCli, 'r') as f:
        input_str = f.read()
    if ptp4l_config in input_str:
        echo_write("configuration already done")
        return 0
    input_str = input_str.rstrip()  # remove any trailing whitespaces
    if input_str.endswith('"'):
        input_str = input_str[:-1]  # remove trailing "
        input_str += ' ' + ptp4l_config + '"'
    else:
        input_str += ' ' +  ptp4l_config
    echo_write("new configuraton for collecting t1-t4: " + input_str)
    with open(ptp4lCli, 'w') as f:
        f.write(input_str)
    reRun_service("ptp4l")
def genT1T2FluctuationReport(output_1_2):
    pass
def recoverTS():
    # concatenate rotated files
    input_file_pmc_ts = "pmcTemp"
    if not os.path.exists(pmcTsFile):
        echo_write("no pmcLogs file found in the current directory")
        return 0
    rotatedFiles=[glob.glob(pmcTsFile+"-*")]
    if len(rotatedFiles[0]) != 0:
        subprocess.run(f"cat {pmcTsFile}-* {pmcTsFile} >> {input_file_pmc_ts}", shell=True) #order of cat should be correct, assuming only one rotated file is present and contains the oldest timestamp
        echo_write("found the pmcLogs with rotated files")
    else:
        subprocess.run(f"cat {pmcTsFile} >> {input_file_pmc_ts}", shell=True)
    # Set input and output file names
    output_1_2 = "ts_1_2_out"
    output_3_4 = "ts_3_4_out"
    # Loop through each line in the input file
    with open(input_file_pmc_ts, "r") as f:
        lines = f.readlines()
    sync_origin_timestamp = None
    sync_event_ingress_timestamp = None
    delayOrigin_timestamp = None
    delayResponseTimestamp = None
    with open(T1_to_T4_tsOut, "w") as file:
        file.write("          T1                   T2                   T3                   T4\n")
    with open(output_1_2, "w") as f1, open(output_3_4, "w") as f2:
        for line in lines:
            # Check if the line contains syncOriginTimestamp or syncEventIngressTimestamp
            if "syncOriginTimestamp" in line:
                # Extract the value of syncOriginTimestamp
                sync_origin_timestamp = line.split()[1]
            elif "syncEventIngressTimestamp" in line:
                # Extract the value of syncEventIngressTimestamp
                sync_event_ingress_timestamp = line.split()[1]
                # Append the two values to the output file
                f1.write(f"{sync_origin_timestamp},{sync_event_ingress_timestamp}\n")
            elif "delayOriginTimestamp" in line:
                # Extract the value of syncEventIngressTimestamp
                delayOrigin_timestamp = line.split()[1]
            elif "delayResponseTimestamp" in line:
                # Extract the value of syncEventIngressTimestamp
                delayResponseTimestamp = line.split()[1]
                f2.write(f"{delayOrigin_timestamp},{delayResponseTimestamp}\n")
                #check all the four timestamps once t4 is seen
                if sync_origin_timestamp != None and sync_event_ingress_timestamp != None:
                    with open(T1_to_T4_tsOut, "a") as file:
                        file.write(f"{sync_origin_timestamp},{sync_event_ingress_timestamp},{delayOrigin_timestamp},{delayResponseTimestamp}\n")
                else: 
                    pass #ignore in case of no T1 and T2 seen but T3 and T4 are found
    analyseTs(T1_to_T4_tsOut) #generate the analysis file based on the timestamps received by ptp4l
    genT1T2FluctuationReport(output_1_2)
    timeNow = datetime.datetime.now().strftime("%Y-%m-%d_T_%H-%M-%S")
    tarFileName = "timestamps-{}.tar.gz".format(timeNow)
    files_to_archive=[T1_to_T4_tsOut,pmcTsFile,output_1_2,output_3_4,scriptLog,AnalyseOutFile]
    files_to_remove=[T1_to_T4_tsOut,output_1_2,output_3_4,AnalyseOutFile]
    with tarfile.open(tarFileName, "w:gz") as tar:
        for file in files_to_archive:
            try:
                tar.add(file)
            except FileNotFoundError:
                echo_write(f"File {file} not found, skipping...")
        for file in rotatedFiles:
            for rot_file in file:
                try:
                    tar.add(rot_file)
                except FileNotFoundError:
                    echo_write(f"File {file} not found, skipping...")
    #clear if any local files if created
    clearLogs(files_to_remove)
    clearLogs([input_file_pmc_ts])

def analyseTs(inputFile):
    with open(inputFile, 'r') as file:
        lines = file.readlines()
    # Remove the first line
    lines = lines[1:]
    # Write the modified content back to the file
    with open(AnalyseFileTemp, 'w') as file:
        file.writelines(lines)
    with open(AnalyseOutFile, 'w') as file:
        file.write("          T1        |          T2        |          T3        |          T4        | raw_delay | raw_offset |\n")
    with open(AnalyseFileTemp, "r") as file:
        # Iterate over each line in the file
        for line in file:
            # Split the line into individual decimal numbers
            numbers_str = line.strip().split(",")
            # Convert each decimal number from string to decimal
            numbers = []
            for num in numbers_str:
                try:
                    number = format(decimal.Decimal(num), ".9f")
                    numbers.append(number)
                except decimal.InvalidOperation:
                    print(f"Decimal Conversion failed for number: {num} at line {line} .. skipping")
                    continue
            if len(numbers) != 4: #if there are no 4 timestamps
                echo_write("found no valid timestamps at line: {}".format(line)) 
                continue
            # Perform arithmetic operation
            t2_t1_diff = format(decimal.Decimal(numbers[1])-decimal.Decimal(numbers[0]),".9f")
            t4_t3_diff = format(decimal.Decimal(numbers[3])-decimal.Decimal(numbers[2]),".9f")
            delay = (decimal.Decimal(t2_t1_diff)+decimal.Decimal(t4_t3_diff))/2
            offset = (decimal.Decimal(t2_t1_diff)-decimal.Decimal(t4_t3_diff))/2
            if offset > 0.000001500 or offset < -0.000001500:
                isIssuePresent = "issueDetected|"
            else: 
                isIssuePresent = ""
            with open(AnalyseOutFile, "a") as f1:
                delay=format(delay,".9f")  #always positive
                offset = "+" + format(offset,".9f") if offset >= 0 else format(offset,".9f")
                f1.write(f"{numbers[0]}|{numbers[1]}|{numbers[2]}|{numbers[3]}|{delay}|{offset}|{isIssuePresent}\n")
    #remove temp files 
    filestoRemove = [AnalyseFileTemp]
    clearLogs(filestoRemove)

def isPtp4lOk(ptp4lTempLog): #returns 1 or true if ok and 0 if not ok 
    # check if nologs are there at all
    with open(ptp4lTempLog, "r") as f:
        content = f.read()
        if "rms" not in content:
            echo_write("no logs found with rms in ptp4l logs")
            return 0
    # check line by line all logs
    # Open the log file and read the contents
    with open(ptp4lTempLog, 'r') as f:
        log_contents = f.read()
        matches = re.findall(r'rms\s+(\d+)', log_contents)
        for rms_value in matches:
            rms_value = int(rms_value)
            if rms_value > RMS_THRESHOLD:
                return 0

    strings_to_check = ['jump', 'tx_timeout', 'SLAVE to UNCALIBRATED', 'SLAVE to LISTENING', 'SLAVE to FAULTY', 'Stopped']
    with open(ptp4lTempLog, 'r') as file:
        file_contents = file.read()
        if any(string in file_contents for string in strings_to_check):
            echo_write("found the issue in ptp4l logs")
            return 0
    return 1

def isPhc2sysOk(phc2sysTempLog): #retunrs 1 if ok and 0 if not ok 
    with open(phc2sysTempLog, "r") as f:
        content = f.read()
        strings_to_check = ['rms','offset']
        if any(s in content for s in strings_to_check):
            pass
        else:
            echo_write("no logs found with rms/ offset in phc2sys logs")
            return 0
        strForRms = None
        for string in strings_to_check:
            if string in content:
                strForRms=string
        matches = re.findall(rf'{strForRms}\s+(\d+)', content)
        for rms_value in matches:
            rms_value = int(rms_value)
            if rms_value > RMS_THRESHOLD:
                return 0
    return 1
def isTimingPodLogOk(): #returns 1 if ok and 0 if not ok
    podname= findtimingPod()
    if podname == None:
        return 0
    duration = "2m"
    command = f"kubectl logs {podname} --since={duration}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    with open(timingMgrLogTemp, "w") as f:
        f.write(process.stdout)
    strings_to_check=['E_PTP_EVT_LOCK_HOLDOVER_EXPIRY','curl_easy_perform() failed']
    if not process.stdout:
        echo_write("could not get the timingpodlogTemp")
        return 0
    elif any(s in process.stdout for s in strings_to_check):
        echo_write("issue found in unifed-timingmgr logs")
        return 0
    return 1
def findtimingPod():
    command = "kubectl get pods -A | grep unified | awk '{print $2}'"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status_name = process.returncode
    podname = process.stdout.strip()
    if len(podname) != 0:
        return podname
    else:
        echo_write("could not find the unified-timingmgr pod")
        return None
def collect_timingPod_logs():
    podname= findtimingPod()
    if podname == None:
        return 0
    command = f"kubectl exec {podname} -- cat /var/log/timing.log"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status_logs = process.returncode
    if status_logs == 0:
        with open(timingMgrLog, "w") as f:
            f.write(process.stdout)
        echo_write("collected the timingmgr pod logs")
        return 1
    command = f"kubectl exec {podname} -- cat /var/log/timingmgr.log"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status_logs = process.returncode
    if status_logs == 0:
        with open(timingMgrLog, "w") as f:
            f.write(process.stdout)
        echo_write("collected the timingmgr pod logs")
        return 1
    command = f"kubectl logs {podname}"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status_logs = process.returncode
    if status_logs == 0:
        with open(timingMgrLog, "w") as f:
            f.write(process.stdout)
        echo_write("collected the timingmgr pod logs")
        return 1
    echo_write("could not collect the timingmgr pod logs though the pod is found")
    return 0

def checkTimingLogs():
    current_time = datetime.datetime.now().strftime("%Y-%m-%d_T_%H-%M-%S")
    timeNow = datetime.datetime.now().strftime("%Y-%m-%d_T_%H-%M-%S")
    tarFileName = "ptp4l_issue-{}.tar.gz".format(timeNow)
    command = f"journalctl -u ptp4l --since \"{timeSlotText}\""
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    with open(ptp4lTempLog, "w") as f:
        f.write(process.stdout)
    command = f"journalctl -u phc2sys --since \"{timeSlotText}\""
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    with open(phc2sysTempLog, "w") as f:
        f.write(process.stdout)
    podname = findtimingPod()
    timingPodLogStatusOk = None
    if podname != None: #check if unified-timing is installed and if yes check the logs otherwise consider logs are fine
        timingPodLogStatusOk = isTimingPodLogOk()
    else:
        timingPodLogStatusOk = True
    if not isPhc2sysOk(phc2sysTempLog) or not isPtp4lOk(ptp4lTempLog) or not timingPodLogStatusOk:
        echo_write("Issue detected in phc2sys or ptp4l logs or timingmgr logs .. let me collect logs!")
        time.sleep(60) # sleep for one minute after the issue
        cmd_ptp4l = f"journalctl -u ptp4l --since \"{timeSlotTextMax}\""
        cmd_phc2sys = f"journalctl -u phc2sys --since \"{timeSlotTextMax}\""
        process = subprocess.run(cmd_ptp4l, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        with open(ptp4lLog, "w") as f:
            f.write(process.stdout)
        process = subprocess.run(cmd_phc2sys, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        with open(phc2sysLog, "w") as f:
            f.write(process.stdout)
        collect_timingPod_logs()
        #tar all the logs collected
        files_to_archive = [ptp4lLog, phc2sysLog, logrotateConfig, timingMgrLog, phc2sysTempLog,
                    ptp4lTempLog, scriptLog, pcapLog, cpuStatsLog,timingMgrLogTemp]
        files_to_remove = [ptp4lLog, phc2sysLog, logrotateConfig, timingMgrLog, phc2sysTempLog,
                    ptp4lTempLog,timingMgrLogTemp]
        rotatedFiles=[glob.glob(pcapLog+"[012]"), glob.glob(cpuStatsLog+"-*")]
        with tarfile.open(tarFileName, "w:gz") as tar:
            for file in files_to_archive:
                try:
                    tar.add(file)
                except FileNotFoundError:
                    echo_write(f"File {file} not found, skipping...")
            for file in rotatedFiles:
                for rot_file in file:
                    try:
                        tar.add(rot_file)
                    except FileNotFoundError:
                        echo_write(f"File {file} not found, skipping...")
        clearLogs(files_to_remove)
        echo_write("done collecting the logs .. pls send us {} file to check".format(tarFileName))
        global instanceNo
        instanceNo = instanceNo + 1
        time.sleep(5)
        return 0
    else:
        echo_write("No issue found yet in ptp4l or phc2sys")
        return 1
def clearLogs(Logs):
    for file in Logs:
        if os.path.exists(file):
            os.remove(file)

def rotate_logs():
    LOG_FILE = os.path.join(CWD, cpuStatsLog)
    PMC_LOG_FILE = os.path.join(CWD, pmcTsFile)
    SCRIPT_LOG = os.path.join(CWD, scriptLog)
    # Define logrotate configuration
    with open(os.path.join(CWD, logrotateConfig), "w") as f:
        f.write(f"{LOG_FILE} {SCRIPT_LOG} {PMC_LOG_FILE}\n")
        f.write("{\n")
        f.write("    su root root\n")
        f.write(f"    size {MAX_SIZE_MB}\n")
        f.write(f"    rotate {MAX_ROTATED_FILES}\n")
        f.write("    dateext\n")
        f.write(f"    olddir {CWD}\n")
        f.write("    dateformat -%s\n")
        f.write("    copytruncate\n")
        f.write("    missingok\n")
        f.write("    nocompress\n")
        f.write("    create\n")
        f.write("}\n")
    # Run logrotate with custom configuration
    os.system(f"logrotate {os.path.join(CWD, logrotateConfig)}")

def takeSarPcapOut():
    #start pcap and sar in bg
    startSarOut()
    startTcpDump()
    #start log rotation in loop while checking the lgos
    while True:
        checkTimingLogs()
        for proc in processes_started:
            if not isPidRunning(proc.pid):
                echo_write("background processes exited .. check the inputs supplied to script")
                return 0
        rotate_logs()
        echo_write("rotating the logs")
        time.sleep(TIME_SLOT_INTVL) #check after 60 sec
def collect_ts_from_pmc():
    # start pmc in background
    configurePtp4lCmdl("--slave_event_monitor=/tmp/foo")
    startPmcAsSystemd()
    #startPmc()
    #start log rotation
    while True:
        for proc in processes_started:
            if not isPidRunning(proc.pid):
                echo_write("background processes exited .. check the inputs supplied to script")
                return 0
        if not is_service_running(serviceName):
            reRun_service(serviceName)
        rotate_logs()
        time.sleep(20)
def takeSarPcapTsOut():
    #func to take pcap, sar, timestamps when issue occurs in ptp4l/phc2sys/timinmgmgr
    #functions used in this are independent and can be used for specific use if needed
    configurePtp4lCmdl("--slave_event_monitor=/tmp/foo")
    startPmcAsSystemd()
    time.sleep(int(int(TIME_SLOT_INTVL)+10))
    startSarOut()
    startTcpDump()
    startDUPingTest()
    #start log rotation in loop while checking the lgos
    while True:
        '''for proc in processes_started:
            if not isPidRunning(proc.pid):
                echo_write("background processes exited .. check the inputs supplied to script")
                return 0'''
        if not is_service_running(serviceName):
            reRun_service(serviceName)
        rotate_logs()
        time.sleep(TIME_SLOT_INTVL) #check after 60 sec
        if checkTimingLogs() == 0: #incase issue detected in ptp4l or phc2sys or timingmgr logs
            #create timestamps tar also
            recoverTS()
def exit_program():
    os.kill(os.getpid(), signal.SIGTERM)
def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

"""
command line parser and calling all functions from here 
"""
signal.signal(signal.SIGTERM, signal_handler)
current_dir = os.getcwd()
echo_write(f"setting current working directory {current_dir} with 777")
os.chmod(current_dir, 0o777)
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:f:s:p:S:h")
except getopt.GetoptError as err:
    echo_write(str(err))
    help()
    exit_program()
for opt, optarg in opts:
    if opt == "-i":
        INTERFACE = optarg
    elif opt == "-s":
        PCAP_MAX_SIZE_MB = optarg
    elif opt == "-h":
        help()
        exit_program()
    elif opt == "-S":
        echo_write("current max size is " + str(MAX_SIZE_MB))
        MAX_SIZE_MB = int(optarg)*int(1000000)
        echo_write("set the rotated timestamps capture file size to " + str(optarg) + " MB")
    elif opt == "-p":
        process = optarg
        if process == "collectTs":
            collect_ts_from_pmc()
        elif process == "recoverTs":
            recoverTS()
        elif process == "analyseTs":
            analyseTs(T1_to_T4_tsOut)
        elif process == "stop":
            configurePtp4lCmdl()
        elif process == "collectPcaps":
            startTcpDump()
        elif process == "writeScriptLog":
            echo_write('writing to script.log')
        elif process == "collectLogs":
            takeSarPcapOut()
        elif process == "collectTsPcapSarLog":
            takeSarPcapTsOut()
        elif process == "checkSar":
            startSarOut()
            time.sleep(60)
        else:
            echo_write("Invalid option for -p: " + optarg)
    else:
        echo_write("Invalid option: -" + opt)
        help()
        exit_program()
exit_program()

