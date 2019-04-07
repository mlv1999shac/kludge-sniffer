#!usr/bin/env python
import socket, struct, binascii



def analyse_tcp_header(packet):
    print("<===============  TCP Header  ===============>")
    tcp_hdr = struct.unpack("!2H2L4H", packet[:20])
    src_port = tcp_hdr[0]
    dst_port = tcp_hdr[1]
    seq_number = tcp_hdr[2]
    ack_number = tcp_hdr[3]
    data_offset = tcp_hdr[4] >> 12
    #reserved = (tcp_hdr[4] >> 6 ) &  #0000 1111 11
    flags = tcp_hdr[4] & 0x003f  # 0000 0000 0011 1111
    urg = flags & 0x0020 # 1 0 0 0 0 0
    ack = flags & 0x0010 # 0 1 0 0 0 0
    psh = flags & 0x0008 # 0 0 1 0 0 0
    rst = flags & 0x0004 # 0 0 0 1 0 0
    syn = flags & 0x0002 # 0 0 0 0 1 0
    fin = flags & 0x0001 # 0 0 0 0 0 1
    window = tcp_hdr[5]
    tcp_chksum = tcp_hdr[6]
    urg_pointer = tcp_hdr[7]
    if urg == 32:
        urg =1

    if ack ==16:
        ack =1

    if psh == 8:
        psh = 1

    if rst == 4:
        rst = 1

    if syn == 2:
        syn =1


    print("\t SRC PORT           :   "+str(src_port))
    print("\t DST PORT           :   "+str(dst_port))
    print("\t Seqence Number     :   "+str(seq_number))
    print("\t Acknowledge Number :   "+str(ack_number))
    #print("\t data offset        :   "+str(data_offset))
    #print("\t <== flags ==> ")
    print("\t [URG | ACK | PSH | RST | SYN | FIN ] :::::: " + "[  "+str(urg) +" |  "+ str(ack) +" |  "+ str(psh) + " |  "+ str(rst) + " |  "+ str(syn) +" |  "+ str(fin)+ " ]")
    #print("\t [  "+str(urg) +" |  "+ str(ack) +"  |  "+ str(psh) + "  |  "+ str(rst) + "  |  "+ str(syn) +"  |  "+ str(fin)+ " ]")
    print("\t Window Size        :   "+str(window))
    #print("\t Check Sum          :   "+str(tcp_chksum))
    #print("\t Urgent Pointer     :   "+str(urg_pointer))


    data = packet[20: ]
    return data




def analyse_ip_header(packet):
    _default_protocol_ = "UDP"
    print("<===============  IP Header  ===============>")
    ip_hdr = struct.unpack("!6H4s4s", packet[:20])
    version = ip_hdr[0] >> 12
    ihl = (ip_hdr[0] >> 8) & 0x0f  #00001111
    tos = (ip_hdr[0]) & 0x00ff  # 0000 0000 1111 1111
    total_length = ip_hdr[1]
    identification = (ip_hdr[2])
    flags = ip_hdr[3] >> 13
    fragment = ip_hdr[3] & 0x1fff # 0001 1111 1111 1111
    ttl = ip_hdr[4] >> 8
    protocol = ip_hdr[4] & 0x00ff  # 0000 0000 1111 1111
    header_chk_sum = ip_hdr[5]
    src_ip = socket.inet_ntoa(ip_hdr[6])
    dst_ip = socket.inet_ntoa(ip_hdr[7])

    #print("\t VERSION           :   " + str(version))
    #print("\t IHL               :   " + str(ihl))
    #print("\t TOS               :   " + str(tos))
    print("\t Total Length      :   " + str(total_length))
    print("\t Identification    :   " + str(identification))
    #print("\t ttl               :   " + str(ttl))
    #print("\t protocol          :   " + str(protocol))
    #print("\t CheckSum          :   " + str(header_chk_sum))
    print("\t SRC IP            :   " + str(src_ip))
    print("\t DST IP            :   " + str(dst_ip))





    packet =packet[20:]
    return packet, protocol




def analyse_ether_header(packet):
    ip_bool =False
    ether_hdr = struct.unpack("!6s6sH",packet[:14])
    dst_mac = binascii.hexlify(ether_hdr[0])
    src_mac = binascii.hexlify(ether_hdr[1])
    type = ether_hdr[2]
    packet = packet[14:]
    #print("<===============  MAC Header  ===============>")
    #print("\t DST MAC : "+ str(dst_mac))
    #print("\t SRC MAC : "+ str(src_mac))
    #print("\t TYPE : " + str(hex(type)))
    if hex(type) == "0x800":
        ip_bool = True

    return packet, ip_bool






def main():

    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
    packet = s.recv(2048)
    no_ether_header, ip_bool = analyse_ether_header(packet)

    if ip_bool:
       no_ip_header, protocol =  analyse_ip_header(no_ether_header)
    else:
        return

    if protocol == 6 :
        raw_data = analyse_tcp_header(no_ip_header)
        print(raw_data)
    if protocol == 17:
        print("$$$$$$$$$$UDP")



while True:
    main()