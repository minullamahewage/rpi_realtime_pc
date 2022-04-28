# Raspberry Pi Real-time Packet Capture

## FYP 17 Group: Fition

- Python Version 3.7.3
- Install `requirements.txt`
- 

### Setup
Server needs to be running: https://github.com/hiranlowe/FitionPredictor<img width="286" alt="image" src="https://user-images.githubusercontent.com/47106053/165825265-486334c4-2e0e-417c-8738-3b81cc34eb5b.png">

`uvicorn app:app --reload --host 0.0.0.0`

1. Login in as super user: `sudo su`
2. Setup Nexmon CSI:
``export PATH=$PATH:/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams
makecsiparams -c 36/80 -C 1 -N 1
pkill wpa_supplicant
ifconfig wlan0 up
nexutil -Iwlan0 -s500 -b -l34 -vKuABEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf "phy" $2}'` interface add mon0 type monitor
ifconfig mon0 up``
3. env file with `SERVER_URL`: `SERVER_URL = "SeverIP:8000";`
4. Run python program: `python3 rtpcu.py`
5. Install libpcap library: `sudo apt-get install libpcap-dev`
6. Compile file: `gcc rtpc.c -lpcap`
7. Run file: `./a.out`
8. 
