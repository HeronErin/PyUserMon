# Python nearby network activity monitor

This project is intended as a school project. It uses Pyshark (a python API for Tshark, a command line version of Wireshark) to monitor how active an area is. All data is anonymized - no one person should ever be able to be tracked with the results from this project. Before you publish your data you should *_shred_* the anon.dat file, which is the "salt" used for generating hashes of subjects' MAC addresses. Furthermore, MAC addresses are reset every-week by a factor determined by the anon.dat file. All timestamps are given a random offset to protect the privacy of the subjects. The output file is shuffled in blocks of 750 packets, meaning it is theoretically impossible for a true timestamp to be determined in a typical operating condition. 


*The subjects' privacy is to be given top priority. *



See datalog.py for how this is mostly implemented.