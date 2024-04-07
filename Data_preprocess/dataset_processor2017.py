from utils.dataset_processor import DatasetProcesser2017

def  preprocess_data_del():
    classes = ['benign',
                'bruteforce-ftp',
                'bruteforce-ssh',
                'dos-slowloris',
                'dos-slowhttptest',
                'dos-hulk',
                'ddos',
                'portscan',
                'webattack',
                'botnet']

    ORIG_DATA_PATH = './IDS/CIC-IDS2017/120_5_flows(delall)'
    DATA_PATH = './IDS/CIC-IDS2017/120_5_flows_delallaaa'

    DatasetProcesser2017(ORIG_DATA_PATH,DATA_PATH,classes).run()


if __name__ == '__main__':
    # preprocess_data_del()

    pass

