import watchdog.events
import watchdog.observers
import time
import os
# import matplotlib.pyplot as plt
import numpy as np
# import seaborn as sns

  
  
class Handler(watchdog.events.PatternMatchingEventHandler):
    def __init__(self):
        # Set the patterns for PatternMatchingEventHandler
        # watchdog.events.PatternMatchingEventHandler.__init__(self, patterns=['*.pcap'],
        #                                                      ignore_directories=True, case_sensitive=False)
                                                             
        watchdog.events.PatternMatchingEventHandler.__init__(self,
                                                             ignore_directories=True, case_sensitive=False)

        self.count = 0
        self.checkNotify = False
        self.packetHandler = PacketHandler()
  
    def on_created(self, event):
        # print("Watchdog received created event - % s." % event.src_path)
        # Event is created, you can process it now
        filename = event.src_path.split("/")[-1]
        # print(filename)
        checkName = "output" + str(self.count) + ".pcap"
        if(filename == checkName):
            if(self.count >= 9):
                self.count = 0
            else:
                self.count += 1
            self.checkNotify = True
        elif(filename=="notify.txt" and self.checkNotify):
            packetFile = "output" + str(self.count-1) + ".pcap"
            self.packetHandler.readFile(packetFile)
  
    def on_modified(self, event):
        # print("Watchdog received modified event - % s." % event.src_path)
        # Event is modified, you can process it now
        filename = event.src_path.split("/")[-1]
        # print(filename)
        checkName = "output" + str(self.count) + ".pcap"
        if(filename == checkName):
            if(self.count >= 9):
                self.count = 0
            else:
                self.count += 1
            self.checkNotify = True
            # print("checking notfy", filename)
        elif(filename=="notify.txt" and self.checkNotify):
            if(self.count == 0):
                packetFile = "output9.pcap"
            else:
                packetFile = "output" + str(self.count-1) + ".pcap"
            self.packetHandler.readFile(packetFile)

class PacketHandler:
    # def __init__(self):
    #     # TODO

    def readFile(self, filename):
        print("reading filename: % s" % filename)
        filePath = "/home/pi/rpi_realtime_pc/" + filename
        print(filePath)
        csi = read_csi(filePath)
        nullsubcarriers  = np.array([x+128 for x in [-128, -127, -126, -125, -124, -123, -1, 0, 1, 123, 124, 125, 126, 127]])
        pilotsubcarriers = np.array([x+128 for x in [-103, -75, -39, -11, 11, 39, 75, 103]])
        csi=np.delete(csi,np.s_[nullsubcarriers],axis=1)
        csi=np.delete(csi,np.s_[pilotsubcarriers],axis=1)
        print("csi_matrix: ", csi)
        # method to read file


def _read_csi_next(pcapfile, csi_size):
    """
    Note: Designed for internal use only.
    
    Parameters
    ----------
        pcapfile : File Object
        csi_size : Expected length of CSI in bytes. NFFT * 4
    """

    # Read Frame Size
    pcapfile.seek(8, os.SEEK_CUR)
    frame_size = int.from_bytes(
        pcapfile.read(4),
        byteorder = 'little',
        signed = False
    )

    # Skip some stuff
    pcapfile.seek(56, os.SEEK_CUR)

    # Read CSI data
    pcapfile.seek(8, os.SEEK_CUR)
    csi = np.frombuffer(
        pcapfile.read(csi_size), 
        dtype = np.int16,
        count = int(csi_size / 2)
    )

    # Skip any zero-padding
    pcapfile.seek((frame_size - csi_size - 60), os.SEEK_CUR)

    return csi

def read_csi(pcap_file_path):
    """
    Read CSI data from PCAP file.
    Supports only 40MHz bandwidth,
    and only one Mac ID. You have
    to remove null subcarriers
    yourself.

    Parameters
    ----------
        pcap_file_path : str
    """

    bandwidth = 80

    NFFT = int(bandwidth * 3.2) # Number of channels in FFT
    chunksize = 1024

    csi  = np.zeros((chunksize, NFFT * 2), dtype = 'int16')

    with open(pcap_file_path, 'rb') as pcapfile:
        filesize = os.stat(pcap_file_path).st_size
        pcapfile.seek(24, os.SEEK_SET)

        npackets = 0
        while pcapfile.tell() < filesize:
            if not (npackets % chunksize):
                csi = np.vstack((csi, np.zeros((chunksize, NFFT * 2), dtype = 'int16')))

            csi[npackets] = _read_csi_next(pcapfile, NFFT * 4)
            
            npackets += 1

    # Convert CSI complex numbers to Magnitude.
    csi_converted = np.abs(
        np.fft.fftshift(csi[:npackets, ::2] + 1.j * csi[:npackets, 1::2], axes=(1,))
    )

    return csi_converted
  
if __name__ == "__main__":
    print("Started Packet Monitoring")
    src_path = "/home/pi/rpi_realtime_pc/"
    event_handler = Handler()
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path=src_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()