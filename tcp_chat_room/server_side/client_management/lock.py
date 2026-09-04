import threading 

"""Lock to ensure only 1 thread can access at a time"""
state_lock = threading.Lock()
ip_lock = threading.Lock()
