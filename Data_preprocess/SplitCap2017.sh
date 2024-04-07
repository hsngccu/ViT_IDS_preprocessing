target_folder="./Original Network Traffic and Log data/"

find "$target_folder" -mindepth 1 -maxdepth 1 -type d | while read -r folder
do

    find "$folder" -mindepth 1 -maxdepth 1 -type f | while read -r file
    do
        echo "tshark file:"
        new_string="-tshark.pcap"
        tfile="${file}${new_string}"
        tshark -F pcap -r "$file" -w "$tfile"
        echo "SplitCap file: $tfile"
        mono SplitCap.exe -r "$tfile" -p 1018 -o "$folder/5_tuple_flows"
    done
done