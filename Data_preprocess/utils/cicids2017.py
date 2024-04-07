from datetime import datetime, timezone, timedelta
import numpy as np


class CicIds2017():
    DATE = {"1":"Monday", "2":"Tuesday", "3":"Wednesday", "4":"Thursday", "5": "Friday"}

    def __init__(self,date_id=None):
        self.DATE_ID = date_id

    def get_m_2_list(self, date_id = None):
        if not date_id:
            date_id = self.DATE_ID
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
        if not date_id:
            date_id = self.DATE_ID
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
            attack_class = ['webattack-bruteforce', 'webattack-xss', 'webattack-sql','infiltration']#,'coolDisk_MAC'
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

    def get_label(self, date_id, pkt, ip_tuple_list, start_end_time):
        if not date_id:
            date_id = self.DATE_ID
        # get information of the first packet
        src_ip = pkt.payload.src
        src_port = pkt.payload.payload.sport
        dst_ip = pkt.payload.dst
        dst_port = pkt.payload.payload.dport
        pkt_ip_tuple = np.array([src_ip, dst_ip], dtype='O')

        # set timezone for time
        tz = timezone(timedelta(hours=-3))#夏令時間加拿大時區-3小時
        arr_time = datetime.fromtimestamp(int(pkt.time), tz)
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
