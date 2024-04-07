# IDS

## Run step
### install environment

      conda env create --file IDS.yaml --name <name>

### CIC-IDS2017

      sh SplitCap2017.sh
      python get_feature2017.py

### CIC-IDS2018

      sh SplitCap2018.sh
      python get_feature2018.py

## Data_Preprocess
1. SplitCap.exe: 使用SplitCap將資料按5-tuple切成一個個pcap

   指令：

         mono SplitCap.exe -r INPUTPCAPFILE -p 1018 -o OUTPUTDIR
   - -s flow: 5-tuple，單向流向
   - -s session or default: 5-tuple，雙向流向
   - -p 並行處理文件最大數量
   - [SplitCap官網](https://www.netresec.com/?page=SplitCap)
   - **<font color=EAC100>SplirCap.sh: 大型資料集流量太大時使用</font>**
      - 執行指令

            sh SplitCap.sh

   - ❗❗注意，資料及內含pcapng檔，SplirCap.exe無法解析，須依以下方式解決：❗❗
      - 安裝套件

            sudo apt install wireshark-common

      - 轉檔指令

            editcap -F pcap <file.pcapng> <newfile.pcap>

2. get_feature.py: 取flow的(byte, packet)，包成.npy
   - IMG_SHAPE: (bytes number, packets number)
   - VERSION:
      - normal: only process normal ip directories
      - malicious(受害者): only process malicious ip directories
   - TRAFFIC_TYPE: TCP/UDP
   - Get_IDS{dataset year}: 將所有bytes保留，並提供方法: runTCP(), runUDP()
   - Get_IDS{dataset year}_del: 將 MAC,IP,Port 刪除，並提供方法: runTCP_del(),runUDP_del()
   - Get_IDS{dataset year}_port: 將 MAC,IP,Port 刪除,Port用隨機方式替換，並提供方法: runTCP_port(), runUDP_port()
   - Get_IDS{dataset year}_rand: 將 MAC,IP,Port 隨機方式替換，並提供方法: runTCP(), runUDP()
