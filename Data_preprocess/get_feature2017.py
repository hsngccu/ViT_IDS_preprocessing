import numpy as np
from scapy.all import *
import glob
from datetime import datetime, timezone, timedelta
import os
from tqdm import tqdm
from multiprocessing import Pool
import pandas as pd
from utils.cicflowmeter.flow import Flow
from utils.cicflowmeter.features.context.packet_direction import PacketDirection


class Get_IDS2017(): # Interface
    DATE = {"1":"Monday", "2":"Tuesday", "3":"Wednesday", "4":"Thursday", "5": "Friday"}
    def __init__(self, paths, date_id, traffic_type, img_shape,save_to = None):
        self.paths = paths
        self.save_to = save_to
        self.date_id = date_id
        self.TRAFFIC_TYPE = traffic_type
        self.IMG_SHAPE = img_shape
        if save_to == None:
            self.directory = f'./IDS/CIC-IDS2017/' \
                            f'{str(self.IMG_SHAPE[0])}_{str(self.IMG_SHAPE[1])}_flows/{self.DATE[date_id]}/{self.TRAFFIC_TYPE}'
        else:
            self.directory = save_to


    def get_m_2_list(self, date_id):
        m_2_list = None
        if date_id == "1":
            m_2_list = []
        elif date_id == "2":
            m_2_list = [[("172.16.0.1", "192.168.10.50")], # bruteforce-ftp
                        [("172.16.0.1", "192.168.10.50")]] # bruteforce-ssh
        elif date_id == "3":
            m_2_list = [[("172.16.0.1", "192.168.10.50")], # dos-slowloris
                        [("172.16.0.1", "192.168.10.50")], # dos-slowhttptest
                        [("172.16.0.1", "192.168.10.50")], # dos-hulk
                        [("172.16.0.1", "192.168.10.50")], # dos-goldeneye
                        [("172.16.0.11", "192.168.10.51")]]# heartbleed
        elif date_id == "4":
            m_2_list = [[("172.16.0.1", "192.168.10.50")], # webattack-bruteforce
                        [("172.16.0.1", "192.168.10.50")], # webattack-xss
                        [("172.16.0.1", "192.168.10.50")], # webattack-sql
                        [('192.168.10.8','205.174.165.73'),('192.168.10.9','205.174.165.73'),('192.168.10.25','205.174.165.73')]] # infiltration
        elif date_id == "5":
            m_2_list = [[('192.168.10.14','205.174.165.73'),('192.168.10.15','205.174.165.73'),('192.168.10.5','205.174.165.73'),('192.168.10.8','205.174.165.73'),('192.168.10.9','205.174.165.73')], # botnet
                        [('172.16.0.1', '192.168.10.50')], # portscan
                        [('172.16.0.1', '192.168.10.50')]] # ddos
        return m_2_list

    def get_attack_time_class(self,date_id):
        start_end_time = []
        attack_class = []
        if date_id == "2":
            # Tuesday, FTP and SSH Patator
            attack_class = ['bruteforce-ftp', 'bruteforce-ssh']
            start_end_time = [
                (datetime(2017, 7, 4, 9, 20), datetime(2017, 7, 4, 10, 20)),
                (datetime(2017, 7, 4, 14), datetime(2017, 7, 4, 15))
            ]
        elif date_id == "3":
            # Wednesday, DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed
            attack_class = ['dos-slowloris', 'dos-slowhttptest', 'dos-hulk', 'dos-goldeneye', 'heartbleed']
            start_end_time = [
                (datetime(2017, 7, 5, 9, 47), datetime(2017, 7, 5, 10, 10)),
                (datetime(2017, 7, 5, 10, 14), datetime(2017, 7, 5, 10, 35)),
                (datetime(2017, 7, 5, 10, 43), datetime(2017, 7, 5, 11)),
                (datetime(2017, 7, 5, 11, 10), datetime(2017, 7, 5, 11, 23)),
                (datetime(2017, 7, 5, 15, 12), datetime(2017, 7, 5, 15, 32))
            ]
        elif date_id == "4":
            # Thursday, Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack--sql','infiltration']#,'coolDisk_MAC'
            start_end_time = [
                (datetime(2017, 7, 6, 9, 20), datetime(2017, 7, 6, 10)),
                (datetime(2017, 7, 6, 10, 15), datetime(2017, 7, 6, 10, 35)),
                (datetime(2017, 7, 6, 10, 40), datetime(2017, 7, 6, 10, 42)),
                # (datetime(2017, 7, 6, 10, 40), datetime(2017, 7, 6, 10, 42))
                [(datetime(2017, 7, 6, 14, 19), datetime(2017, 7, 6, 14, 21)),
                (datetime(2017, 7, 6, 14, 33), datetime(2017, 7, 6, 14, 35)),
                (datetime(2017, 7, 6, 14, 53), datetime(2017, 7, 6, 15)),
                (datetime(2017, 7, 6, 15, 4), datetime(2017, 7, 6, 15, 45))]
            ]
        elif date_id == "5":
            # Friday, botnet
            attack_class = ['botnet','portscan','ddos']
            start_end_time = [
                (datetime(2017, 7, 7, 10, 2), datetime(2017, 7, 11, 2)),
                (datetime(2017, 7, 7, 13, 55), datetime(2017, 7, 7, 15, 29)),
                (datetime(2017, 7, 7, 15, 56), datetime(2017, 7, 7, 16, 16))
            ]
        return start_end_time, attack_class

    def is_infiltration_tuple(self,pkt_ip_tuple,pkt_arr_time, ip_tuple_list,start_end_time_list):
        start_end_time_list = np.array(start_end_time_list, dtype='O')
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and ((start_end_time_list[0]<=pkt_arr_time<=start_end_time_list[1]).all(1).any()):
            return True
        else:
            return False

    def is_webattack_tuple(self,pkt_ip_tuple,pkt_dstport,pkt_arr_time, ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and pkt_dstport ==80 and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def is_heartbleed_tuple(self,pkt_ip_tuple,pkt_srcport,pkt_dstport,pkt_arr_time,ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and pkt_srcport == 45022 and pkt_dstport ==444 and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def is_dos_tuple(self,pkt_ip_tuple,pkt_dstport,pkt_arr_time, ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and pkt_dstport ==80 and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def is_FTPpatator_tuple(self,pkt_ip_tuple,pkt_dstport,pkt_arr_time, ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and pkt_dstport ==21 and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def is_SSHpatator_tuple(self,pkt_ip_tuple,pkt_dstport,pkt_arr_time, ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and pkt_dstport ==22 and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def is_other_malicious_tuple(self,pkt_ip_tuple,pkt_arr_time, ip_tuple_list,start_end_time):
        if ((ip_tuple_list == pkt_ip_tuple).all(1).any()) and (start_end_time[0]<=pkt_arr_time<=start_end_time[1]):
            return True
        else:
            return False

    def save_np_files(self, date_id, b_flows, m_flows, attack_class):
        # list to numpy array
        for i in range(len(m_flows)):
            m_flows[i] = np.asarray(m_flows[i])
        b_flows = np.asarray(b_flows)

        # make directories
        directory = self.directory

        if not os.path.exists(directory):
            os.makedirs(directory)

        print(f'Number of each class: ')
        print('-' * 50)

        for i, a in enumerate(attack_class):
            np.save(f'{directory}/{a}_t', m_flows[i], allow_pickle=False)
            print(f'{a} is {len(m_flows[i])}')

        np.save(f'{directory}/benign_t', b_flows, allow_pickle=False)
        print(f'benign is {len(b_flows)}')

    def record_error_pcap(self,path,date_id,type,file_name):
        if not os.path.exists(path):
            os.makedirs(path)
        with open(f'{path}/{date_id}_{type}_errorpcap.txt', 'a') as file:
            file.write(f'{file_name}/n')

    def preprocess_flow(self, pkts):
        pass

    def get_label(self, date_id, pkts, ip_tuple_list, start_end_time):
        # get information of the first packet
        src_ip = pkts[0].payload.src
        src_port = pkts[0].payload.payload.sport
        dst_ip = pkts[0].payload.dst
        dst_port = pkts[0].payload.payload.dport
        pkt_ip_tuple = np.array([src_ip, dst_ip], dtype='O')

        # set timezone for time
        tz = timezone(timedelta(hours=-3))#夏令時間加拿大時區-3小時
        arr_time = datetime.fromtimestamp(int(pkts[0].time), tz)
        arr_time = arr_time.replace(tzinfo=None)

        # categorize flows to benign and malicious
        label = 0   # default is benign

        if date_id == "2":
            for index, t in enumerate(start_end_time):# index 0=ftp, 1=ssh
                if index==0 and self.is_FTPpatator_tuple(pkt_ip_tuple,dst_port,arr_time, ip_tuple_list[index],t):
                    label = index + 1
                elif self.is_SSHpatator_tuple(pkt_ip_tuple,dst_port,arr_time, ip_tuple_list[index],t):
                    label = index + 1
        elif date_id == "3":
            for index, t in enumerate(start_end_time):# DoS(index=0~3), Heartbleed(index=4)
                if index<4 and self.is_dos_tuple(pkt_ip_tuple,dst_port,arr_time, ip_tuple_list[index],t):
                    label = index + 1
                elif self.is_heartbleed_tuple(pkt_ip_tuple,src_port,dst_port,arr_time, ip_tuple_list[index],t):
                    label = index + 1

        elif date_id == "4":
            for index, t in enumerate(start_end_time): # webattack
                if index<3 and self.is_webattack_tuple(pkt_ip_tuple,dst_port,arr_time, ip_tuple_list[index],t):
                    label = index + 1
                elif index == 4 and self.is_infiltration_tuple(pkt_ip_tuple,arr_time, ip_tuple_list[index],t):
                    label = index + 1
        else:
            for index, t in enumerate(start_end_time):
                if self.is_other_malicious_tuple(pkt_ip_tuple,arr_time, ip_tuple_list[index],t):
                    label = index + 1
        return label

    def get_used_pkt(self, pkts):
        if self.TRAFFIC_TYPE == 'TCP':
            pkts = pkts[3:self.IMG_SHAPE[1] + 3]
        else:
            pkts = pkts[:self.IMG_SHAPE[1]]

        return pkts

    def run(self):
        # m_2_list is a list of tuples, which contains all attack-victim combinations(source ip, destination ip).
        m_2_list = self.get_m_2_list(self.date_id)

        # get attack time
        start_end_time, attack_class = self.get_attack_time_class(self.date_id)

        # read pcap dirs
        dirs = self.paths


        b_flows = []
        m_flows = [[] for _ in range(len(attack_class))]

        print(f'Date: {self.DATE[self.date_id]}, img_shape: {self.IMG_SHAPE}, traffic_type: {self.TRAFFIC_TYPE}')
        for d in tqdm(dirs):
            dirname = d.split('/')[-1]
            # print(f"{d}/*{TRAFFIC_TYPE}*")
            files = glob.glob(d)
            # 尋找檔案名沒有包含這些ip則直接設為benign
            if any([(dirname.replace('-','.')).find(p[1]) != 0 for p_list in m_2_list for p in p_list]):
                for f in files:
                    try:
                        pkts = rdpcap(f, count=(self.IMG_SHAPE[1] + 3))
                    except (Scapy_Exception, EOFError):
                        continue
                    # check for skip tcp connection in packet
                    if self.TRAFFIC_TYPE == 'TCP' and len(pkts) < 4:
                        continue
                    label = self.get_label(self.date_id, pkts, m_2_list, start_end_time)
                    pkts = self.get_used_pkt(pkts)
                    flow = self.preprocess_flow(pkts)

                    if label == 0:
                        b_flows.append(flow)
                    else:
                        c = label - 1
                        m_flows[c].append(flow)

                    del pkts
            else:
                for f in files:
                    try:
                        pkts = rdpcap(f, count=(self.IMG_SHAPE[1] + 3))
                    except (Scapy_Exception, EOFError):
                        continue

                    # check for skip tcp connection in packet
                    if self.TRAFFIC_TYPE == 'TCP' and len(pkts) < 4:
                        continue
                    pkts = self.get_used_pkt(pkts)
                    flow = self.preprocess_flow(pkts)
                    b_flows.append(flow)
                    del pkts

            del files
        # save files
        self.save_np_files(self.date_id, b_flows, m_flows, attack_class)

class Get_IDS2017_rand(Get_IDS2017): #Randing MAC IP Port
    def __init__(self, paths, date_id, traffic_type, img_shape,save_to = None):
        if save_to != None:
            directory = save_to
        else:
            directory = f'./IDS/CIC-IDS2017/{str(img_shape[0])}_{str(img_shape[1])}_flows(rand)/{self.DATE[date_id]}/{traffic_type}'
        super().__init__(paths, date_id, traffic_type, img_shape, save_to=directory)

        # b_flows, m_flows, attack_class = self.run(self.date_id,self.data_paths)

    def preprocess_flow(self, pkts):
        flow = []

        for pkt in pkts:  # get the first img_shape[1] packets
            # pkt.show()

            # anonymize packet
            pkt.src = str(RandMAC())
            pkt.dst = str(RandMAC())

            try:
                pkt.payload.src = str(RandIP())
            except (Scapy_Exception, OSError):
                # continue
                pkt.payload.src = str(RandIP6())

            try:
                pkt.payload.dst = str(RandIP())
            except (Scapy_Exception, OSError):
                # continue
                pkt.payload.dst = str(RandIP6())

            pkt.payload.payload.sport = int(RandShort())
            pkt.payload.payload.dport = int(RandShort())

            # get the first img_shape[0] bytes
            pkt_head = [byte for byte in raw(pkt)]
            pkt_head.extend([0] * self.IMG_SHAPE[0])  # padding
            flow.extend(pkt_head[:self.IMG_SHAPE[0]])

        # if the flow has too few packets, padding again
        size = (self.IMG_SHAPE[0] * self.IMG_SHAPE[1])
        if len(flow) < size:
            flow.extend([0] * size)
            flow = flow[:size]
        return flow

    def run(self):
        # m_2_list is a list of tuples, which contains all attack-victim combinations(source ip, destination ip).
        m_2_list = self.get_m_2_list(self.date_id)

        # get attack time
        start_end_time, attack_class = self.get_attack_time_class(self.date_id)

        # read pcap dirs
        dirs = self.paths

        b_flows = []
        m_flows = [[] for _ in range(len(attack_class))]

        print(f'Date: {self.DATE[self.date_id]}, img_shape: {self.IMG_SHAPE}, traffic_type: {self.TRAFFIC_TYPE}')
        for d in tqdm(dirs):
            dirname = d.split('/')[-1]
            files = glob.glob(d)
            # check if d is victim ip
            if any([dirname.find(p[1]) != 0 for p in m_2_list]):

                for f in files:
                    try:
                        pkts = rdpcap(f, count=(self.IMG_SHAPE[1] + 3))
                    except (Scapy_Exception, EOFError):
                        continue

                    # check for skip tcp connection in packet
                    if self.TRAFFIC_TYPE == 'TCP' and len(pkts) < 4:
                        continue
                    label = self.get_label(self.date_id, pkts, m_2_list, start_end_time)
                    pkts = self.get_used_pkt(pkts)
                    flow = self.preprocess_flow(pkts)

                    if label == 0:
                        b_flows.append(flow)
                    else:
                        c = label - 1
                        m_flows[c].append(flow)

                    del pkts
            else:
                for f in files:
                    try:
                        pkts = rdpcap(f, count=(self.IMG_SHAPE[1] + 3))
                    except (Scapy_Exception, EOFError):
                        continue

                    # check for skip tcp connection in packet
                    if self.TRAFFIC_TYPE == 'TCP' and len(pkts) < 4:
                        continue
                    pkts = self.get_used_pkt(pkts)
                    flow = self.preprocess_flow(pkts)
                    b_flows.append(flow)

                    del pkts

            del files
        # save files
        self.save_np_files(self.date_id, b_flows, m_flows, attack_class)

class Get_IDS2017_del(Get_IDS2017): #delete IP, Mac, Port
    def __init__(self, paths, date_id, traffic_type, img_shape, save_to = None, version="victim"):
        if save_to != None:
            directory = save_to
        else:
            directory = f'./IDS/CIC-IDS2017/{str(img_shape[0])}_{str(img_shape[1])}_flows(delall)/{self.DATE[date_id]}/{traffic_type}'
        super().__init__(paths, date_id, traffic_type, img_shape, save_to=directory)
    def preprocess_flow(self, pkts):
        max_size = self.IMG_SHAPE[0]-24
        flow = []
        # get the first img_shape[1] packets
        for pkt in pkts:
            # get the first img_shape[0] bytes
            pkt_head = [byte for byte in raw(pkt)]

            pkt_head.extend([0] *max_size)  # padding

            # delete Destination and Source MAC,IP Port
            for start,end in [(0,11),(26,37)] :
                pkt_head[start:end+1] = [None]*(end-start+1)
            pkt_head = [x for x in pkt_head if x is not None]

            flow.extend(pkt_head[:max_size])

        # if the flow has too few packets, padding again
        size = max_size* self.IMG_SHAPE[1]
        if len(flow) < size:
            flow.extend([0] * size)
            flow = flow[:size]
        return flow

class Get_IDS2017_port(Get_IDS2017): #delete MAC IP Port, randing port
    def __init__(self, paths, date_id, traffic_type, img_shape, save_to = None, version="victim"):
        if save_to != None:
            directory = save_to
        else:
            directory = f'./IDS/CIC-IDS2017/' \
                            f'{str(img_shape[0])}_{str(img_shape[1])}_flows(port)/{self.DATE[date_id]}/{traffic_type}'
        super().__init__(paths, date_id, traffic_type, img_shape, save_to=directory)

    def preprocess_flow(self, pkts):
        max_size = self.IMG_SHAPE[0]-20
        flow = []
        for pkt in pkts:  # get the first img_shape[1] packets

            # get the first img_shape[0] bytes
            pkt.payload.payload.sport = int(RandShort())
            pkt.payload.payload.dport = int(RandShort())
            pkt_head = [byte for byte in raw(pkt)]

            pkt_head.extend([0] *max_size)  # padding

            # delete Destination and Source MAC,IP Port
            for start,end in [(0,11),(26,33)] :
                pkt_head[start:end+1] = [None]*(end-start+1)
            pkt_head = [x for x in pkt_head if x is not None]

            flow.extend(pkt_head[:max_size])

        # if the flow has too few packets, padding again
        size = max_size* self.IMG_SHAPE[1]
        if len(flow) < size:
            flow.extend([0] * size)
            flow = flow[:size]
        return flow

DATE = {"1":"Monday", "2":"Tuesday", "3":"Wednesday", "4":"Thursday", "5": "Friday"}
# img_shape = (120, 5)

def runTCP_del(date_id):
    paths = glob.glob(f'./CIC-IDS-2017/Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*TCP*')
    Get_IDS2017_del(paths, date_id, traffic_type = 'TCP', img_shape=(120, 5)).run()

def runUDP_del(date_id):
    paths = glob.glob(f'./CIC-IDS-2017/Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*UDP*')
    Get_IDS2017_del(paths, date_id, traffic_type = 'UDP', img_shape=(120, 5)).run()

def runTCP_port(date_id):
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*TCP*')
    Get_IDS2017_port(paths, date_id, traffic_type = 'TCP', img_shape=(60, 3) ).run()

def runUDP_port(date_id):
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*UDP*')
    Get_IDS2017_port(paths, date_id, traffic_type = 'UDP', img_shape=(60, 3)).run()




if __name__ == '__main__':

    IDs = ['1','2','3','4','5']


    with Pool(5) as p:
        # p.map(runTCP_del, IDs)
        # p.map(runUDP_del, IDs)
        # p.map(runTCP_port, IDs)
        # p.map(runUDP_port, IDs)
        pass