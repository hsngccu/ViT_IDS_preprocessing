

target_folder="./Original Network Traffic and Log data/Tuesday-20-02-2018"

find "$target_folder/pcap" -mindepth 1 -maxdepth 1 -type f | while read -r folder #-type f(file),d(dir)

do
    echo "Processing file: $folder"

    {
        mono SplitCap.exe -r "$folder" -p 1018 -o "$target_folder/5_tuple_flows"
    } || {
        echo "error file: $folder"
        newfolder=$(echo "$folder" | sed 's/\b.pcap\b//g')

        new_string="-new.pcap"
        newfolder="${folder}${new_string}"
        editcap -F pcap "$folder" "$newfolder"

        mono SplitCap.exe -r "$newfolder" -p 1018 -o "$target_folder/5_tuple_flows"
    }
done
