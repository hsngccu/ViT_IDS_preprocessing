from utils.dataset_processor import DatasetProcesser


def  preprocess_data_del():
    classes = ['benign',
                'bruteforce-ftp',
                'bruteforce-ssh',
                'dos-goldeneye',
                'dos-slowloris',
                'dos-hulk',
                'ddos-loic-http',
                'ddos-hoic',
                'webattack',
                'botnet',]
    ORIG_DATA_PATH = './IDS/CIC-IDS2018/60_3_flows(delall)'
    DATA_PATH = './IDS/CIC-IDS2018/delall'
    DatasetProcesser(ORIG_DATA_PATH,DATA_PATH,classes).run()

def  preprocess_data_port():
    classes = ['benign',
                'bruteforce-ftp',
                'bruteforce-ssh',
                'dos-goldeneye',
                'dos-slowloris',
                'dos-hulk',
                'ddos-loic-http',
                'ddos-hoic',
                'webattack',
                'botnet',]
    ORIG_DATA_PATH = './IDS/CIC-IDS2018/60_3_flows(randport)'
    DATA_PATH = './IDS/CIC-IDS2018/randport'
    DatasetProcesser(ORIG_DATA_PATH,DATA_PATH,classes).run()

if __name__ == '__main__':
    preprocess_data_del()
    # preprocess_data_port()
    pass

