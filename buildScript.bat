mkdir src\main\java\com\nomura\pcapsniffer
copy Main.java src\main\java\com\nomura\pcapsniffer 
call mvn clean install
java -jar target\pcapsniffer-1.0-SNAPSHOT-jar-with-dependencies.jar 64x8burst.eth2.pcap