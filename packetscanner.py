from scapy.all import *
from scapy.layers.http import *
import datetime
from termcolor import colored
import sys


    


while True:


    print("Do you want to print raw data (Y / N) ?")

    try:
        print_raw = str(input(">>> "))
        if "Y" in print_raw.upper():
            print_raw = "Y"
            break
        elif "N" in print_raw.upper():
            print_raw = "N"
            break

        else:
            print(" INVALID INPUT ")

    except:
        print("INVALID INPUT")


FormatOutput = ("{:<18}{:<35}{:<30}{:<15}{:<15}{:<20}{:<20}{:<}")
FormatExtraOutput = "{:<153}{:<}"


print(FormatOutput.format("Time","Source IP", "Destination IP","L2","L3","L4","L6","DESCRIPTION"))

print("")

        

while True:
    extra_info = ""
    
    extra_info_L = []

    packetlayers = []

    try:
    
        packets = sniff(count = 1)

    except PermissionError:
        print(colored("YOU MUST BE ROOT TO SNIFF PACKETS","red"))
        sys.exit()

    time = datetime.datetime.now()
    time = str(time)

    time = time.split(" ")

    time = time[1]


    packet = packets[0]

    layers = packet.layers()

    for i in layers:
        i = str(i)
        layerarray = i.split(".")

        protocol = layerarray[-1][0:-2]

        packetlayers.append(protocol)




    if packet.haslayer(TCP):
        srcport = str(packet[TCP].sport)
        dstport = str(packet[TCP].dport)


    elif packet.haslayer(UDP):

        srcport = str(packet[UDP].sport)
        dstport = str(packet[UDP].dport)
        


    
    try:

        dstIP = str(packet[IP].dst)
        srcIP = str(packet[IP].src)

    except:

        
        try:
            dstIP = str(packet[IPv6].dst)
            srcIP = str(packet[IPv6].src)

        except:
            continue






    dstIP = dstIP +":"+dstport
    srcIP = srcIP + ":"+srcport


    if packet.haslayer(HTTP) or packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        pass


        
#--------------------------------------------------------------------------------------------------------------------------------

    if packet.haslayer(TCP):



        




        flg = ""

        chars = {
            "A":"ACK",
            "S":"SYN",
            "F":"FIN",
            "R":"RST",
            "P":"PSH",
            "U":"URG",
            "E":"ECE",
            "C":"CWR"
            
            }
        flag = str(packet[TCP].flags)



        for char in flag:
            flg = flg + chars[char]




        extra_info = extra_info + "[" + flg + "] | Sequence Number = "+ str(packet[TCP].seq) + " | Acknowlegement Number = " + str(packet[TCP].ack)

        extra_info_L.append(extra_info)


        
#------------------------------------------------------------------------------------------------------------------------------------------------------

    if packet.haslayer(BOOTP):





        request_types = {1:"DHCP DISCOVER",
                         2:"DHCP OFFER",
                         3:"DHCP REQUEST",
                         4:"DHCP ACK"}





        try:

            info = packet[DHCP].options

            user_mac = packet[Ether].src


            request_type_num = info[0][1]

            if request_type_num != 3:
                print(packet.show())

            request_type = request_types[request_type_num]

            if request_type_num == 1:
                pass

            elif request_type_num == 2:
                pass
            elif request_type_num == 3 :

                req_addr = info [4][1]
                
                extra_info = str(request_type) + " | " + str(user_mac) + " requested the address " + str(req_addr)

                extra_info_L.append(extra_info)

                pass
            elif request_type_num == 4:
                extra_info = str(request_type) + " | " + str(server_id) + "leased address " + str(packet[BOOTP].yiaddr) + " to "+ str(packet[Ether].dst) + " for " + str(lease_time) + "seconds"

                extra_info_L.append(extra_info)
                pass
            else:
                pass






        except:
            print("CRITICAL FAILURE")
            print(packet.show())



        #------------------------------------------------------------------------------------------------------------------
    elif packet.haslayer(DNS):


        reqORresp = int(packet[DNS].qr)

        


        if reqORresp == 0:
            numQuestions = str(packet[DNS].qdcount)
            
            extra_info = "MADE "+numQuestions + " QUERIES : " 

            
            for question in packet[DNS].qd:
                requested_service = str(question.qname.decode())
                extra_info = extra_info + requested_service

                extra_info_L.append(extra_info)

                extra_info = "                 "



        elif reqORresp == 1:



            record_types = { 1:"A",
                             28:"AAAA",
                             5:"CNAME",
                             65:"HTTPS",
                             15:"MX",
                             12:"PTR",
                             33:"SRV",
                             16:"TXT",
                             47:"NSEC",
                             41:"OPT"}


            

            for answer in packet[DNS].an:
                record_type = answer.type

                record_type = record_types[record_type]

                service_name = answer.rrname



                try:

                    service_dnslooked = answer.rdata

                    

                except:
                    try:
                        service_dnslooked = answer.target

                    except:
                        service_dnslooked = "NOT YET PROGRAMMED"








                if record_type == "A":

                    extra_info = str(service_name , "utf-8") + " has IPv4 address : " + str(service_dnslooked) 

                    extra_info_L.append(extra_info)


                    
                    pass
                elif record_type == "AAAA":
                    extra_info = str(service_name,"utf-8") + " has IPv6 address : " + str(service_dnslooked) 

                    extra_info_L.append(extra_info)


                    
                    pass
                elif record_type == "HTTPS":
                    pass
                elif record_type == "MX":
                    pass
                elif record_type == "PTR":

                    extra_info = str(service_name.decode()) + " has instance: "
                    extra_info = extra_info + str(service_dnslooked,"utf-8")

                    extra_info_L.append(extra_info)
                    
                    pass
                elif record_type == "TXT":

                    extra_info =  "Details about " + str(service_name.decode()) + ": "

                    extra_info_L.append(extra_info)

                    for i in service_dnslooked:
                        extra_info = "     " + i.decode()

                        extra_info_L.append(extra_info)
                        

                elif record_type == "SRV":
                    extra_info = str(service_name.decode()) + " running on hostname " + str(service_dnslooked,"utf-8") + " on port " +str(answer.port)

                    extra_info_L.append(extra_info)

                    
                    pass
                else:
                    continue



                


            for response in packet[DNS].ar:
                record_type = response.type

                record_type = record_types[record_type]


                
                service_name = response.rrname


                try:

                    service_dnslooked = response.rdata


                except:
                    try:
                        service_dnslooked = response.target

                    except:
                        service_dnslooked = "NOT YET PROGRAMMED TO HANDLE "



                if record_type == "A":

                    extra_info = str(service_name , "utf-8") + " has IPv4 address : " + str(service_dnslooked) 

                    extra_info_L.append(extra_info)


                    
                    pass
                elif record_type == "AAAA":
                    extra_info = str(service_name,"utf-8") + " has IPv6 address : " + str(service_dnslooked)

                    extra_info_L.append(extra_info)


                    
                    pass
                elif record_type == "HTTPS":
                    pass
                elif record_type == "MX":
                    pass
                elif record_type == "PTR":

                    extra_info = str(service_name,"utf-8") + " has instance: "
                    extra_info = extra_info + str(service_dnslooked,"utf-8")


                    extra_info_L.append(extra_info)
                    
                elif record_type == "TXT":

                    extra_info =  "Details about " + str(service_name.decode()) + ": "

                    extra_info_L.append(extra_info)

                    for i in service_dnslooked:
                        extra_info = "     " + i.decode()

                        extra_info_L.append(extra_info)

                        
                        
                    pass

                elif record_type == "SRV":
                    extra_info = str(service_name.decode()) + " running on hostname " + str(service_dnslooked,"utf-8") + " on port" +str(response.port) +"\n"

                    extra_info_L.append(extra_info)

                    
                    pass
                else:
                    continue




    elif packet.haslayer(ICMPv6MLReport2):
        print(packet.show())

        for layer in packet:
            print(str(layer))

        for response in packet[ICMPv6MLReport2].records:
            if response.rtype == 4:
                extra_info = "Device requested to join mDNS group " + str(response.dst)
                extra_info_L.append(extra_info)
                
            else:
                pass
        


#--------------------------------------------------------------------------------------------------------------------


    else:
        pass
            
    

    try:
        if extra_info_L[0] == "":
            pass

    except:
        extra_info_L.append(" ")





    
    try:
        print(FormatOutput.format(time,srcIP,dstIP,packetlayers[0],packetlayers[1],packetlayers[2],packetlayers[3],colored(extra_info_L[0],"green")))

        for i in extra_info_L[1:]:
            print(FormatExtraOutput.format("",colored(i,"green")))

        

            

        
    except:
        
        try:
            print(FormatOutput.format(time,srcIP,dstIP,packetlayers[0],packetlayers[1],packetlayers[2],"NONE",colored(extra_info_L[0],"green")))


        except Exception as j:
            print(j)
            continue            


    if packet.haslayer(Raw):

        if print_raw == "Y":


            raw_output = "RAW DATA: " + str(packet[Raw].load)

            print(colored(raw_output , "blue"))


        else:
            pass


    
