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


class Get_IDS2018(): # Interface
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    def __init__(self, paths, date_id, traffic_type, img_shape,save_to = None):
        self.paths = paths
        self.save_to = save_to
        self.date_id = date_id
        self.TRAFFIC_TYPE = traffic_type
        self.IMG_SHAPE = img_shape
        if save_to == None:
            self.directory = f'./IDS/CIC-IDS2018/' \
                            f'{str(self.IMG_SHAPE[0])}_{str(self.IMG_SHAPE[1])}_flows/{self.DATE[date_id]}/{self.TRAFFIC_TYPE}'
        else:
            self.directory = save_to

        # b_flows, m_flows, attack_class = self.run(self.date_id,self.data_paths)

    def get_m_2_list(self, date_id):
        m_2_list = None
        if date_id == "0214":
            m_2_list = [("18.221.219.4", "172.31.69.25"), ("13.58.98.64", "172.31.69.25")]
        elif date_id == "0215":
            m_2_list = [("18.219.211.138", "172.31.69.25"), ("18.217.165.70", "172.31.69.25")]
        elif date_id == "0216":
            m_2_list = [("13.59.126.31", "172.31.69.25"), ("18.219.193.20", "172.31.69.25")]
        elif date_id == "0220":
            m_2_list = [("18.218.115.60", "172.31.69.25"), ("18.219.9.1", "172.31.69.25"),
                        ("18.219.32.43", "172.31.69.25"), ("18.218.55.126", "172.31.69.25"),
                        ("52.14.136.135", "172.31.69.25"), ("18.219.5.43", "172.31.69.25"),
                        ("18.216.200.189", "172.31.69.25"), ("18.218.229.235", "172.31.69.25"),
                        ("18.218.11.51", "172.31.69.25"), ("18.216.24.42", "172.31.69.25")]
        elif date_id == "0221":
            m_2_list = [("18.218.115.60", "172.31.69.28"), ("18.219.9.1", "172.31.69.28"),
                        ("18.219.32.43", "172.31.69.28"), ("18.218.55.126", "172.31.69.28"),
                        ("52.14.136.135", "172.31.69.28"), ("18.219.5.43", "172.31.69.28"),
                        ("18.216.200.189", "172.31.69.28"), ("18.218.229.235", "172.31.69.28"),
                        ("18.218.11.51", "172.31.69.28"), ("18.216.24.42", "172.31.69.28")]
        elif date_id == "0222":
            m_2_list = [("18.218.115.60", "172.31.69.28")]
        elif date_id == "0223":
            m_2_list = [("18.218.115.60", "172.31.69.28")]
        elif date_id == "0228":
            m_2_list = [("13.58.225.34", "172.31.69.24"), ("172.31.69.24", "13.58.225.34")]
        elif date_id == "0301":
            m_2_list = [("13.58.225.34", "172.31.69.13"), ("172.31.69.13", "13.58.225.34")]
        elif date_id == "0302":
            m_2_list = [("18.219.211.138", "172.31.69.23"), ("18.219.211.138", "172.31.69.17"),
                        ("18.219.211.138", "172.31.69.14"), ("18.219.211.138", "172.31.69.12"),
                        ("18.219.211.138", "172.31.69.10"), ("18.219.211.138", "172.31.69.8"),
                        ("18.219.211.138", "172.31.69.6"), ("18.219.211.138", "172.31.69.26"),
                        ("18.219.211.138", "172.31.69.29"), ("18.219.211.138", "172.31.69.30"),
                        ("172.31.69.23", "18.219.211.138"), ("172.31.69.17", "18.219.211.138"),
                        ("172.31.69.14", "18.219.211.138"), ("172.31.69.12", "18.219.211.138"),
                        ("172.31.69.10", "18.219.211.138"), ("172.31.69.8", "18.219.211.138"),
                        ("172.31.69.6", "18.219.211.138"), ("172.31.69.26", "18.219.211.138"),
                        ("172.31.69.29", "18.219.211.138"), ("172.31.69.30", "18.219.211.138")
                        ]
        return m_2_list

    def get_attack_time_class(self, date_id):
        start_end_time = []
        attack_class = []
        if date_id == "0214":
            attack_class = ['bruteforce-ftp', 'bruteforce-ssh']
            start_end_time = [
                (datetime(2018, 2, 14, 10, 32), datetime(2018, 2, 14, 12, 9)),
                (datetime(2018, 2, 14, 14, 1), datetime(2018, 2, 14, 15, 31))
            ]
        elif date_id == "0215":
            attack_class = ['dos-goldeneye', 'dos-slowloris']
            start_end_time = [
                (datetime(2018, 2, 15, 9, 26), datetime(2018, 2, 15, 10, 9)),
                (datetime(2018, 2, 15, 10, 59), datetime(2018, 2, 15, 11, 40))
            ]
        elif date_id == "0216":
            attack_class = ['bruteforce-ftp', 'dos-hulk']
            start_end_time = [
                (datetime(2018, 2, 16, 10, 12), datetime(2018, 2, 16, 11, 8)),
                (datetime(2018, 2, 16, 13, 45), datetime(2018, 2, 16, 14, 19))
            ]
        elif date_id == "0220":
            attack_class = ['ddos-loic-http', 'ddos-loic-udp']
            start_end_time = [
                (datetime(2018, 2, 20, 10, 12), datetime(2018, 2, 20, 11, 17)),
                (datetime(2018, 2, 20, 13, 13), datetime(2018, 2, 20, 13, 32))
            ]
        elif date_id == "0221":
            attack_class = ['ddos-loic-udp', 'ddos-hoic']
            start_end_time = [
                (datetime(2018, 2, 21, 10, 9), datetime(2018, 2, 21, 10, 43)),
                (datetime(2018, 2, 21, 14, 5), datetime(2018, 2, 21, 15, 5))
            ]
        elif date_id == "0222":
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack-sql']
            start_end_time = [
                (datetime(2018, 2, 22, 10, 17), datetime(2018, 2, 22, 11, 24)),
                (datetime(2018, 2, 22, 13, 50), datetime(2018, 2, 22, 14, 29)),
                (datetime(2018, 2, 22, 16, 15), datetime(2018, 2, 22, 16, 29))
            ]
        elif date_id == "0223":
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack-sql']
            start_end_time = [
                (datetime(2018, 2, 23, 10, 3), datetime(2018, 2, 23, 11, 3)),
                (datetime(2018, 2, 23, 13), datetime(2018, 2, 23, 14, 10)),
                (datetime(2018, 2, 23, 15, 5), datetime(2018, 2, 23, 15, 18))
            ]
        elif date_id == "0228":
            attack_class = ['infiltration']
            start_end_time = [
                (datetime(2018, 2, 28, 10, 50), datetime(2018, 2, 28, 12, 5)),
                (datetime(2018, 2, 28, 13, 42), datetime(2018, 2, 28, 14, 40))
            ]
        elif date_id == "0301":
            attack_class = ['infiltration']
            start_end_time = [
                (datetime(2018, 3, 1, 9, 57), datetime(2018, 3, 1, 10, 55)),
                (datetime(2018, 3, 1, 14), datetime(2018, 3, 1, 15, 37))
            ]
        elif date_id == "0302":
            attack_class = ['botnet']
            start_end_time = [
                (datetime(2018, 3, 2, 10, 11), datetime(2018, 3, 2, 11, 34)),
                (datetime(2018, 3, 2, 14, 24), datetime(2018, 3, 2, 15, 55))
            ]

        return start_end_time, attack_class

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

    def get_label(self, date_id, pkts, m_2_list, start_end_time):
        # get information of the first packet
        src_ip = pkts[0].payload.src
        # src_port = pkts[0].payload.payload.sport
        dst_ip = pkts[0].payload.dst
        # dst_port = pkts[0].payload.payload.dport
        # pkt_4_tuple = np.array([src_ip, src_port, dst_ip, dst_port], dtype='O')
        pkt_2_array = np.array([src_ip, dst_ip], dtype='O')

        # set timezone for time
        tz = timezone(timedelta(hours=-4))#夏令時間-3,平時-4
        arr_time = datetime.fromtimestamp(int(pkts[0].time), tz)

        arr_time = arr_time.replace(tzinfo=None)

        # categorize flows to benign and malicious
        label = 0  # default is benign
        if date_id == "0228" or date_id == "0301" or date_id == "0302":
            if ((m_2_list == pkt_2_array).all(1).any()) and (any([t[0] <= arr_time <= t[1] for t in start_end_time])):
                label = 1

        #修正CIC-IDS2018 (SSH Patator)錯誤
        elif date_id == "0214" and ([start_end_time[1][0] <= arr_time <= start_end_time[1][1]]) and pkts[0].dport == 21:
            label = 1

        else:
            for i, t in enumerate(start_end_time):
                if ((m_2_list == pkt_2_array).all(1).any()) and (t[0] <= arr_time <= t[1]):
                    label = i + 1

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
            # check if d is victim ip
            if any([(dirname.replace('-','.')).find(p[1]) != 0 for p in m_2_list]):
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

class Get_IDS2018_rand(Get_IDS2018): #Randing MAC IP Port
    def __init__(self, paths, date_id, traffic_type, img_shape,save_to = None):
        if save_to == None:
            self.directory = f'./IDS/CIC-IDS2018/' \
                            f'{str(self.IMG_SHAPE[0])}_{str(self.IMG_SHAPE[1])}_flows(rand)/{self.DATE[date_id]}/{self.TRAFFIC_TYPE}'
        else:
            self.directory = save_to
        super().__init__(paths, date_id, traffic_type, img_shape, save_to=self.directory)

        # b_flows, m_flows, attack_class = self.run(self.date_id,self.data_paths)

    def get_m_2_list(self, date_id):
        m_2_list = None
        if date_id == "0214":
            m_2_list = [("18.221.219.4", "172.31.69.25"), ("13.58.98.64", "172.31.69.25")]
        elif date_id == "0215":
            m_2_list = [("18.219.211.138", "172.31.69.25"), ("18.217.165.70", "172.31.69.25")]
        elif date_id == "0216":
            m_2_list = [("13.59.126.31", "172.31.69.25"), ("18.219.193.20", "172.31.69.25")]
        elif date_id == "0220":
            m_2_list = [("18.218.115.60", "172.31.69.25"), ("18.219.9.1", "172.31.69.25"),
                        ("18.219.32.43", "172.31.69.25"), ("18.218.55.126", "172.31.69.25"),
                        ("52.14.136.135", "172.31.69.25"), ("18.219.5.43", "172.31.69.25"),
                        ("18.216.200.189", "172.31.69.25"), ("18.218.229.235", "172.31.69.25"),
                        ("18.218.11.51", "172.31.69.25"), ("18.216.24.42", "172.31.69.25")]
        elif date_id == "0221":
            m_2_list = [("18.218.115.60", "172.31.69.28"), ("18.219.9.1", "172.31.69.28"),
                        ("18.219.32.43", "172.31.69.28"), ("18.218.55.126", "172.31.69.28"),
                        ("52.14.136.135", "172.31.69.28"), ("18.219.5.43", "172.31.69.28"),
                        ("18.216.200.189", "172.31.69.28"), ("18.218.229.235", "172.31.69.28"),
                        ("18.218.11.51", "172.31.69.28"), ("18.216.24.42", "172.31.69.28")]
        elif date_id == "0222":
            m_2_list = [("18.218.115.60", "172.31.69.28")]
        elif date_id == "0223":
            m_2_list = [("18.218.115.60", "172.31.69.28")]
        elif date_id == "0228":
            m_2_list = [("13.58.225.34", "172.31.69.24"), ("172.31.69.24", "13.58.225.34")]
        elif date_id == "0301":
            m_2_list = [("13.58.225.34", "172.31.69.13"), ("172.31.69.13", "13.58.225.34")]
        elif date_id == "0302":
            m_2_list = [("18.219.211.138", "172.31.69.23"), ("18.219.211.138", "172.31.69.17"),
                        ("18.219.211.138", "172.31.69.14"), ("18.219.211.138", "172.31.69.12"),
                        ("18.219.211.138", "172.31.69.10"), ("18.219.211.138", "172.31.69.8"),
                        ("18.219.211.138", "172.31.69.6"), ("18.219.211.138", "172.31.69.26"),
                        ("18.219.211.138", "172.31.69.29"), ("18.219.211.138", "172.31.69.30"),
                        ("172.31.69.23", "18.219.211.138"), ("172.31.69.17", "18.219.211.138"),
                        ("172.31.69.14", "18.219.211.138"), ("172.31.69.12", "18.219.211.138"),
                        ("172.31.69.10", "18.219.211.138"), ("172.31.69.8", "18.219.211.138"),
                        ("172.31.69.6", "18.219.211.138"), ("172.31.69.26", "18.219.211.138"),
                        ("172.31.69.29", "18.219.211.138"), ("172.31.69.30", "18.219.211.138")
                        ]
        return m_2_list

    def get_attack_time_class(self, date_id):
        start_end_time = []
        attack_class = []
        if date_id == "0214":
            attack_class = ['bruteforce-ftp', 'bruteforce-ssh']
            start_end_time = [
                (datetime(2018, 2, 14, 10, 32), datetime(2018, 2, 14, 12, 9)),
                (datetime(2018, 2, 14, 14, 1), datetime(2018, 2, 14, 15, 31))
            ]
        elif date_id == "0215":
            attack_class = ['dos-goldeneye', 'dos-slowloris']
            start_end_time = [
                (datetime(2018, 2, 15, 9, 26), datetime(2018, 2, 15, 10, 9)),
                (datetime(2018, 2, 15, 10, 59), datetime(2018, 2, 15, 11, 40))
            ]
        elif date_id == "0216":
            attack_class = ['bruteforce-ftp', 'dos-hulk']
            start_end_time = [
                (datetime(2018, 2, 16, 10, 12), datetime(2018, 2, 16, 11, 8)),
                (datetime(2018, 2, 16, 13, 45), datetime(2018, 2, 16, 14, 19))
            ]
        elif date_id == "0220":
            attack_class = ['ddos-loic-http', 'ddos-loic-udp']
            start_end_time = [
                (datetime(2018, 2, 20, 10, 12), datetime(2018, 2, 20, 11, 17)),
                (datetime(2018, 2, 20, 13, 13), datetime(2018, 2, 20, 13, 32))
            ]
        elif date_id == "0221":
            attack_class = ['ddos-loic-udp', 'ddos-hoic']
            start_end_time = [
                (datetime(2018, 2, 21, 10, 9), datetime(2018, 2, 21, 10, 43)),
                (datetime(2018, 2, 21, 14, 5), datetime(2018, 2, 21, 15, 5))
            ]
        elif date_id == "0222":
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack-sql']
            start_end_time = [
                (datetime(2018, 2, 22, 10, 17), datetime(2018, 2, 22, 11, 24)),
                (datetime(2018, 2, 22, 13, 50), datetime(2018, 2, 22, 14, 29)),
                (datetime(2018, 2, 22, 16, 15), datetime(2018, 2, 22, 16, 29))
            ]
        elif date_id == "0223":
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack-sql']
            start_end_time = [
                (datetime(2018, 2, 23, 10, 3), datetime(2018, 2, 23, 11, 3)),
                (datetime(2018, 2, 23, 13), datetime(2018, 2, 23, 14, 10)),
                (datetime(2018, 2, 23, 15, 5), datetime(2018, 2, 23, 15, 18))
            ]
        elif date_id == "0228":
            attack_class = ['infiltration']
            start_end_time = [
                (datetime(2018, 2, 28, 10, 50), datetime(2018, 2, 28, 12, 5)),
                (datetime(2018, 2, 28, 13, 42), datetime(2018, 2, 28, 14, 40))
            ]
        elif date_id == "0301":
            attack_class = ['infiltration']
            start_end_time = [
                (datetime(2018, 3, 1, 9, 57), datetime(2018, 3, 1, 10, 55)),
                (datetime(2018, 3, 1, 14), datetime(2018, 3, 1, 15, 37))
            ]
        elif date_id == "0302":
            attack_class = ['botnet']
            start_end_time = [
                (datetime(2018, 3, 2, 10, 11), datetime(2018, 3, 2, 11, 34)),
                (datetime(2018, 3, 2, 14, 24), datetime(2018, 3, 2, 15, 55))
            ]

        return start_end_time, attack_class

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


    def preprocess_flow(self, pkts):
        flow = []

        # for pkt in pkts[3:IMG_SHAPE[1] + 3]:
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

        # add flow timestamps
        # flow.append(int(pkts[0].time))

        return flow

    def get_label(self, date_id, pkts, m_2_list, start_end_time):
        # get information of the first packet
        src_ip = pkts[0].payload.src
        # src_port = pkts[0].payload.payload.sport
        dst_ip = pkts[0].payload.dst
        # dst_port = pkts[0].payload.payload.dport
        # pkt_4_tuple = np.array([src_ip, src_port, dst_ip, dst_port], dtype='O')
        pkt_2_array = np.array([src_ip, dst_ip], dtype='O')

        # set timezone for time
        tz = timezone(timedelta(hours=-4))#夏令時間-3,平時-4
        arr_time = datetime.fromtimestamp(int(pkts[0].time), tz)

        arr_time = arr_time.replace(tzinfo=None)

        # categorize flows to benign and malicious
        label = 0  # default is benign
        if date_id == "0228" or date_id == "0301" or date_id == "0302":
            if ((m_2_list == pkt_2_array).all(1).any()) and (any([t[0] <= arr_time <= t[1] for t in start_end_time])):
                label = 1

        #修正CIC-IDS2018 (SSH Patator)錯誤
        elif date_id == "0214" and ([start_end_time[1][0] <= arr_time <= start_end_time[1][1]]) and pkts[0].dport == 21:
            label = 1

        else:
            for i, t in enumerate(start_end_time):
                if ((m_2_list == pkt_2_array).all(1).any()) and (t[0] <= arr_time <= t[1]):
                    label = i + 1

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

class Get_IDS2018_del(Get_IDS2018): #delete IP, Mac, Port
    def __init__(self, paths, date_id, traffic_type, img_shape, save_to = None, version="victim"):
        if save_to != None:
            directory = save_to
        else:
            directory = f'./IDS/CIC-IDS2018/' \
                            f'{str(img_shape[0])}_{str(img_shape[1])}_flows(delall)/{self.DATE[date_id]}/{traffic_type}'
        super().__init__(paths, date_id, traffic_type, img_shape, save_to=directory)
    def preprocess_flow(self, pkts):
        max_size = self.IMG_SHAPE[0]-24
        flow = []
        for pkt in pkts:  # get the first img_shape[1] packets

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

class Get_IDS2018_port(Get_IDS2018): #delete MAC IP Port, randing port
    def __init__(self, paths, date_id, traffic_type, img_shape, save_to = None, version="victim"):
        if save_to != None:
            directory = save_to
        else:
            directory = f'./IDS/CIC-IDS2018/' \
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

            # delete Destination and Source MAC,IP
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

def runTCP_del(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}

    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*TCP*')
    Get_IDS2018_del(paths, date_id, traffic_type = 'TCP', img_shape=(60, 3) ).run()

def runUDP_del(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*UDP*')
    Get_IDS2018_del(paths, date_id, traffic_type = 'UDP', img_shape=(60, 3)).run()

def runTCP_port(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*TCP*')
    Get_IDS2018_port(paths, date_id, traffic_type = 'TCP', img_shape=(60, 3) ).run()

def runUDP_port(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*UDP*')
    Get_IDS2018_port(paths, date_id, traffic_type = 'UDP', img_shape=(60, 3)).run()

def runTCP(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*TCP*')
    Get_IDS2018(paths, date_id, traffic_type = 'TCP', img_shape=(60, 3) ).run()

def runUDP(date_id):
    DATE = {"0214": "Wednesday-14-02-2018", "0215": "Thursday-15-02-2018", "0216": "Friday-16-02-2018",
            "0220": "Tuesday-20-02-2018", "0221": "Wednesday-21-02-2018", "0222": "Thursday-22-02-2018",
            "0223": "Friday-23-02-2018", "0228": "Wednesday-28-02-2018", "0301": "Thursday-01-03-2018",
            "0302": "Friday-02-03-2018"}
    paths = glob.glob(f'./Original Network Traffic and Log data/{DATE[date_id]}/5_tuple_flows/*UDP*')
    Get_IDS2018(paths, date_id, traffic_type = 'UDP', img_shape=(60, 3)).run()


if __name__ == '__main__':

    IDs = ['0214', '0215', '0216', '0220', '0221', '0222', '0223', '0228', '0301', '0302']


    with Pool(10) as p:
        p.map(runTCP_del, IDs)
        p.map(runUDP_del, IDs)
        # p.map(runTCP_port, IDs)
        # p.map(runUDP_port, IDs)


